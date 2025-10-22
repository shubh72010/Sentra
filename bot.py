# bot.py
# Anti-spam Discord bot using perceptual hashing (imagehash + Pillow)
# - Reads DISCORD_BOT_TOKEN from environment
# - Loads images from ./spam_images/ and stores their pHashes
# - On new attachments: computes pHash in-memory and compares to known hashes
# - Admin commands to add/remove/list/reload spam fingerprints
# - Doesn't rely on filenames (filename collisions safe)
#
# Run: python bot.py
# Make sure to set env var DISCORD_BOT_TOKEN before starting.

import os
import io
import asyncio
import logging
from typing import Dict, List

import aiohttp
import discord
from discord.ext import commands
from PIL import Image, ImageOps, UnidentifiedImageError
import imagehash
import json

# ---------- CONFIG ----------
ENV_TOKEN_NAME = "DISCORD_BOT_TOKEN"
SPAM_FOLDER = "spam_images"      # folder included in repo (sanitized images)
HASHES_FILE = "hashes.json"      # cached hashes (optional)
HASH_TOLERANCE = int(os.environ.get("HASH_TOLERANCE", "5"))  # Hamming distance tolerance
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
    """Compute perceptual hash for a Pillow Image."""
    # Normalize orientation and mode
    img = ImageOps.exif_transpose(img).convert("RGB")
    return imagehash.phash(img)

def load_hashes_from_folder(folder: str = SPAM_FOLDER) -> Dict[str, imagehash.ImageHash]:
    """Scan a folder of images and compute pHashes. Returns dict filename->hash."""
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
    """Save textual hashes to JSON (hash hex strings). Optional helpful cache."""
    try:
        payload = {k: str(v) for k, v in hashes.items()}
        with open(out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        log.info(f"Saved {len(hashes)} hashes to {out}")
    except Exception as e:
        log.exception("Failed saving hashes.json: %s", e)

def load_hashes_from_json(infile: str = HASHES_FILE) -> Dict[str, imagehash.ImageHash]:
    """Load hashes from JSON file if present."""
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
    """Download remote image into memory and return bytes."""
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                raise RuntimeError(f"Failed to GET {url} -> {resp.status}")
            return await resp.read()

async def compute_phash_from_bytes(data: bytes) -> imagehash.ImageHash:
    """Open image bytes with Pillow and compute phash."""
    with io.BytesIO(data) as b:
        with Image.open(b) as img:
            return compute_phash_from_pil(img)

def is_similar_hash(h1: imagehash.ImageHash, h2: imagehash.ImageHash, tol: int = HASH_TOLERANCE) -> bool:
    """Return True if two pHashes are within tolerance (hamming distance)."""
    return (h1 - h2) <= tol

# ---------- Bot events & core logic ----------

@bot.event
async def on_ready():
    global known_hashes
    log.info(f"Logged in as {bot.user} (id: {bot.user.id})")
    # Load hashes from JSON if available; otherwise compute from folder
    loaded_from_json = load_hashes_from_json()
    if loaded_from_json:
        known_hashes = loaded_from_json
    else:
        known_hashes = load_hashes_from_folder()
        # save as cache
        save_hashes_to_json(known_hashes)
    log.info(f"Known spam fingerprints: {len(known_hashes)}")

@bot.event
async def on_message(message: discord.Message):
    # ignore self
    if message.author == bot.user:
        return

    # Only inspect messages with attachments
    if message.attachments:
        for att in message.attachments:
            # Quick skip: check content type exists and starts with 'image'
            ctype = getattr(att, "content_type", None)
            if ctype and not ctype.startswith("image"):
                continue
            try:
                # download image bytes
                data = await download_image_bytes(att.url)
                # compute phash
                att_hash = await compute_phash_from_bytes(data)
            except Exception as e:
                log.warning(f"Failed to process attachment {att.filename}: {e}")
                continue

            # Compare to known hashes
            for spam_name, spam_hash in known_hashes.items():
                if is_similar_hash(att_hash, spam_hash):
                    # Found match -> delete and notify
                    try:
                        await message.delete()
                        # Try to DM mods? For simplicity send to channel with auto-delete
                        try:
                            await message.channel.send(f"{ALERT_MESSAGE} Removed an image posted by {message.author.mention}.", delete_after=6)
                        except discord.Forbidden:
                            log.warning("No permission to send message in channel to notify.")
                        log.info(f"Deleted spam image from {message.author} (match: {spam_name}) in {message.guild}/{message.channel}")
                    except discord.Forbidden:
                        log.error("Missing permissions to delete messages.")
                    except Exception as e:
                        log.exception("Failed deleting message: %s", e)
                    # break out — we've handled this message
                    await bot.process_commands(message)  # allow commands after handling
                    return

    await bot.process_commands(message)

# ---------- Admin commands (manage server only) ----------

def is_guild_mod():
    """Check predicate for commands: requires Manage Guild or Administrator."""
    async def predicate(ctx):
        perms = ctx.author.guild_permissions
        if perms.manage_guild or perms.administrator or perms.manage_messages:
            return True
        raise commands.MissingPermissions(["manage_guild"])
    return commands.check(predicate)

@bot.command(name="reload_hashes")
@is_guild_mod()
async def reload_hashes(ctx):
    """Reload spam fingerprints from spam_images/ and from hashes.json."""
    global known_hashes
    known_hashes = load_hashes_from_folder()
    save_hashes_to_json(known_hashes)
    await ctx.send(f"Reloaded hashes. Total known spam fingerprints: {len(known_hashes)}", delete_after=6)

@bot.command(name="list_hashes")
@is_guild_mod()
async def list_hashes(ctx):
    """List known spam filenames (their aliases) and count."""
    if not known_hashes:
        await ctx.send("No spam fingerprints loaded.", delete_after=6)
        return
    lines = [f"{i+1}. {name}  —  {str(h)}" for i, (name, h) in enumerate(known_hashes.items())]
    # If too long, upload as file
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
    """
    Add the attached image(s) to spam_images/ and update fingerprints.
    Usage: Reply to an image with !add_spam, or send an image with the command and attach it.
    """
    attachments = ctx.message.attachments
    if not attachments:
        await ctx.send("Attach one or more images to add as spam fingerprints (or reply to a message with attachments).", delete_after=8)
        return

    added = 0
    for att in attachments:
        # only accept images
        ctype = getattr(att, "content_type", None)
        if ctype and not ctype.startswith("image"):
            continue
        try:
            data = await download_image_bytes(att.url)
            # open and sanitize/save as PNG in spam folder
            with Image.open(io.BytesIO(data)) as img:
                img = ImageOps.exif_transpose(img).convert("RGB")
                # generate safe filename: use a timestamp + original name
                safe_name = f"{int(asyncio.get_event_loop().time()*1000)}_{os.path.basename(att.filename)}"
                safe_name = safe_name.replace(" ", "_")
                out_path = os.path.join(SPAM_FOLDER, safe_name)
                os.makedirs(SPAM_FOLDER, exist_ok=True)
                img.save(out_path, format="PNG", optimize=True)
                # compute phash and add to known_hashes
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
    """
    Remove a spam fingerprint by filename key (the name under spam_images/).
    Usage: !remove_spam filename.png
    """
    if name not in known_hashes:
        await ctx.send("Name not found among known fingerprints.", delete_after=6)
        return
    # delete file if exists
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

# bot alive thingy

from flask import Flask
import threading

app = Flask('')

@app.route('/')
def home():
    return "Sentra bot is alive!"

def run():
    app.run(host='0.0.0.0', port=10000)

threading.Thread(target=run).start()

# ---------- Start bot ----------

def main():
    token = os.environ.get(ENV_TOKEN_NAME)
    if not token:
        log.critical(f"Environment variable {ENV_TOKEN_NAME} not set. Exiting.")
        return
    bot.run(token)

if __name__ == "__main__":
    main()

# --- Fake web server to keep Render alive (Free Plan fix) ---
from threading import Thread
from flask import Flask

app = Flask('')

@app.route('/')
def home():
    return "🛡️ Sentra is running and connected to Discord!"

def run_web():
    app.run(host='0.0.0.0', port=10000)

Thread(target=run_web).start()
# --- End of fake web server ---