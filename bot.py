# bot.py
# Anti-spam Discord bot using perceptual hashing (imagehash + Pillow)
# Handles both attachments and embedded Discord media links
# Admin commands to manage spam fingerprints
# Keep-alive Flask server for Render Free plan

import os
import io
import asyncio
import logging
from typing import Dict
import threading
import json

import aiohttp
import discord
from discord.ext import commands
from PIL import Image, ImageOps, UnidentifiedImageError
import imagehash
from flask import Flask

# ---------- CONFIG ----------
ENV_TOKEN_NAME = "DISCORD_BOT_TOKEN"
SPAM_FOLDER = "spam_images"
HASHES_FILE = "hashes.json"
HASH_TOLERANCE = int(os.environ.get("HASH_TOLERANCE", "5"))
ALERT_MESSAGE = "⚠️ A spam image was removed."
# ----------------------------

# Logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("anti-spam-bot")

# Intents
intents = discord.Intents.default()
intents.message_content = True
intents.messages = True
intents.guilds = True

bot = commands.Bot(command_prefix="!", intents=intents)

# In-memory store: {filename: imagehash}
known_hashes: Dict[str, imagehash.ImageHash] = {}

# ---------- Utility functions ----------

def compute_phash_from_pil(img: Image.Image) -> imagehash.ImageHash:
    img = ImageOps.exif_transpose(img).convert("RGB")
    return imagehash.phash(img)

def load_hashes_from_folder(folder: str = SPAM_FOLDER) -> Dict[str, imagehash.ImageHash]:
    results: Dict[str, imagehash.ImageHash] = {}
    if not os.path.isdir(folder):
        log.info(f"Spam folder '{folder}' does not exist — creating.")
        os.makedirs(folder, exist_ok=True)
        return results
    for fn in os.listdir(folder):
        path = os.path.join(folder, fn)
        if not os.path.isfile(path):
            continue
        try:
            with Image.open(path) as img:
                ph = compute_phash_from_pil(img)
                results[fn] = ph
                log.info(f"Loaded spam image '{fn}', phash={str(ph)}")
        except UnidentifiedImageError:
            log.warning(f"Skipped non-image file in spam folder: {fn}")
        except Exception as e:
            log.exception(f"Error loading '{fn}': {e}")
    return results

def save_hashes_to_json(hashes: Dict[str, imagehash.ImageHash], out: str = HASHES_FILE):
    try:
        payload = {k: str(v) for k, v in hashes.items()}
        with open(out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        log.info(f"Saved {len(hashes)} hashes to {out}")
    except Exception as e:
        log.exception("Failed saving hashes.json: %s", e)

def load_hashes_from_json(infile: str = HASHES_FILE) -> Dict[str, imagehash.ImageHash]:
    if not os.path.isfile(infile):
        return {}
    try:
        with open(infile, "r", encoding="utf-8") as f:
            data = json.load(f)
        out = {k: imagehash.hex_to_hash(v) for k, v in data.items()}
        log.info(f"Loaded {len(out)} hashes from {infile}")
        return out
    except Exception as e:
        log.exception("Failed reading hashes.json: %s", e)
        return {}

async def download_image_bytes(url: str) -> bytes:
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                raise RuntimeError(f"Failed to GET {url} -> {resp.status}")
            return await resp.read()

def is_similar_hash(h1: imagehash.ImageHash, h2: imagehash.ImageHash, tol: int = HASH_TOLERANCE) -> bool:
    return (h1 - h2) <= tol

# ---------- Bot events ----------

@bot.event
async def on_ready():
    global known_hashes
    log.info(f"Logged in as {bot.user} (id: {bot.user.id})")
    loaded_from_json = load_hashes_from_json()
    if loaded_from_json:
        known_hashes = loaded_from_json
    else:
        known_hashes = load_hashes_from_folder()
        save_hashes_to_json(known_hashes)
    log.info(f"Known spam fingerprints: {len(known_hashes)}")

@bot.event
async def on_message(message: discord.Message):
    if message.author == bot.user:
        return

    images_to_check = []

    # 1️⃣ Add attachments
    for att in message.attachments:
        ctype = getattr(att, "content_type", None)
        if ctype and not ctype.startswith("image"):
            continue
        try:
            data = await download_image_bytes(att.url)
            img = Image.open(io.BytesIO(data))
            images_to_check.append(img)
        except Exception as e:
            log.warning(f"Failed to process attachment {att.filename}: {e}")

    # 2️⃣ Add Discord media links in content
    for word in message.content.split():
        if word.startswith("https://media.discordapp.net/") or word.startswith("https://cdn.discordapp.com/"):
            try:
                url = word.split("?")[0]  # remove query params
                data = await download_image_bytes(url)
                img = Image.open(io.BytesIO(data))
                images_to_check.append(img)
            except Exception as e:
                log.warning(f"Failed to fetch image from link {word}: {e}")

    # 3️⃣ Check all images
    for img in images_to_check:
        phash = compute_phash_from_pil(img)
        for spam_name, spam_hash in known_hashes.items():
            if is_similar_hash(phash, spam_hash):
                try:
                    await message.delete()
                    try:
                        await message.channel.send(
                            f"{ALERT_MESSAGE} Removed an image posted by {message.author.mention}.",
                            delete_after=6
                        )
                    except discord.Forbidden:
                        log.warning("No permission to send message in channel to notify.")
                    log.info(f"Deleted spam image from {message.author} (match: {spam_name}) in {message.guild}/{message.channel}")
                except discord.Forbidden:
                    log.error("Missing permissions to delete messages.")
                except Exception as e:
                    log.exception("Failed deleting message: %s", e)
                await bot.process_commands(message)
                return

    await bot.process_commands(message)

# ---------- Admin commands ----------

def is_guild_mod():
    async def predicate(ctx):
        perms = ctx.author.guild_permissions
        if perms.manage_guild or perms.administrator or perms.manage_messages:
            return True
        raise commands.MissingPermissions(["manage_guild"])
    return commands.check(predicate)

@bot.command(name="reload_hashes")
@is_guild_mod()
async def reload_hashes(ctx):
    global known_hashes
    known_hashes = load_hashes_from_folder()
    save_hashes_to_json(known_hashes)
    await ctx.send(f"Reloaded hashes. Total known spam fingerprints: {len(known_hashes)}", delete_after=6)

@bot.command(name="list_hashes")
@is_guild_mod()
async def list_hashes(ctx):
    if not known_hashes:
        await ctx.send("No spam fingerprints loaded.", delete_after=6)
        return
    lines = [f"{i+1}. {name}  —  {str(h)}" for i, (name, h) in enumerate(known_hashes.items())]
    text = "\n".join(lines)
    if len(text) < 1900:
        await ctx.send(f"Known spam fingerprints ({len(known_hashes)}):\n```\n{text}\n```", delete_after=20)
    else:
        fp = io.StringIO(text)
        fp.seek(0)
        await ctx.send(file=discord.File(fp, filename="known_hashes.txt"))

@bot.command(name="add_spam")
@is_guild_mod()
async def add_spam(ctx):
    attachments = ctx.message.attachments
    if not attachments:
        await ctx.send("Attach one or more images to add as spam fingerprints.", delete_after=8)
        return

    added = 0
    for att in attachments:
        ctype = getattr(att, "content_type", None)
        if ctype and not ctype.startswith("image"):
            continue
        try:
            data = await download_image_bytes(att.url)
            with Image.open(io.BytesIO(data)) as img:
                img = ImageOps.exif_transpose(img).convert("RGB")
                safe_name = f"{int(asyncio.get_event_loop().time()*1000)}_{os.path.basename(att.filename)}"
                safe_name = safe_name.replace(" ", "_")
                os.makedirs(SPAM_FOLDER, exist_ok=True)
                out_path = os.path.join(SPAM_FOLDER, safe_name)
                img.save(out_path, format="PNG", optimize=True)
                ph = compute_phash_from_pil(img)
                known_hashes[os.path.basename(out_path)] = ph
                added += 1
        except Exception as e:
            log.exception("Failed adding spam image: %s", e)
            continue

    save_hashes_to_json(known_hashes)
    await ctx.send(f"Added {added} image(s) to spam fingerprints.", delete_after=8)

@bot.command(name="remove_spam")
@is_guild_mod()
async def remove_spam(ctx, *, name: str):
    if name not in known_hashes:
        await ctx.send("Name not found among known fingerprints.", delete_after=6)
        return
    path = os.path.join(SPAM_FOLDER, name)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except Exception as e:
        log.warning(f"Could not remove file {path}: {e}")
    known_hashes.pop(name, None)
    save_hashes_to_json(known_hashes)
    await ctx.send(f"Removed fingerprint: {name}", delete_after=6)

@bot.command(name="ping")
async def ping(ctx):
    await ctx.send("pong", delete_after=5)

# ---------- Flask keep-alive for Render ----------

app = Flask('')

@app.route('/')
def home():
    return "🛡️ Sentra is running and connected to Discord!"

def run_web():
    app.run(host='0.0.0.0', port=10000)

threading.Thread(target=run_web, daemon=True).start()

# ---------- Start bot ----------

def main():
    token = os.environ.get(ENV_TOKEN_NAME)
    if not token:
        log.critical(f"Environment variable {ENV_TOKEN_NAME} not set. Exiting.")
        return
    bot.run(token)

if __name__ == "__main__":
    main()