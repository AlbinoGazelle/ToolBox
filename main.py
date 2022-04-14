from time import sleep
import discord #duhhhh
import logging #used for useful logging output (and checking for heartbeat)
import json #used for parsing config.json to avoid keys being leaked to github
from discord import channel
from discord.colour import Color #used to make requests to various API endpoints
from discord.ext import commands
from datetime import datetime
import requests
import asyncio
import base64
from urllib.parse import urlparse
import os.path
from zipfile import ZipFile
import pyminizip
import os
#setup logging
logging.basicConfig(
    level = logging.INFO,
    format = '[%(levelname)s][%(asctime)s] - %(message)s',
    datefmt = '%Y-%m-%d %H:%M:%S',
)


#init bot
intents = discord.Intents.default()
bot = commands.Bot(command_prefix='?', intents=intents)

#parse config file for tokens and keys
with open('config.json') as config_file:
    config = json.load(config_file)

#do stuff when the bot is ready
@bot.event
async def on_ready():
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=f"👁️"))
    print(f'Bot connected as {bot.user}')

#validate urls
def is_url(url):
  try:
    result = urlparse(url)
    return all([result.scheme, result.netloc])
  except ValueError:
    return False


@bot.command(pass_context=True)
async def pfp(ctx):
    try:
        pfp = ctx.message.mentions[0].avatar_url
        embed=discord.Embed(title=f"{ctx.message.mentions[0]}'s avatar", color=Color.green())
        embed.set_image(url=(pfp))
        await ctx.send(embed=embed)
    except IndexError:
        await ctx.send("You must mention a user!")


# Returns base64 representation of a given URL without padding
# Parameters:
#  url: Valid HTTP URL
#    type: string
# Returns:
#  base64 representation of url 
#    type: string

async def get_url(url):
    return base64.b64encode(url.encode('ascii')).decode('ascii').strip("=")

# Submits a GET request to VirusTotal's API to receive data on a URL
# Parameters: 
#  url: virustotal API url with base64 encode URL string as id
#    type: string
# Returns:
#  HTTP response
#   type: response object
async def get_vt_url_info(url):
    headers = {
        "Accept" : "application/json",
        "x-apikey" : config['vt']
    }
    print(f"getting info on {url}")
    response = requests.request("GET", url, headers=headers)
    return response

# Submits a POST request to VirusTotal's API to submit a URL for analysis
# Parameters:
#  url: virustotal API endpoint
#    type: string
#  data: URL to submit to VirusTotal
#    type: string
# Returns:
#  HTTP response:
#   type: response object
async def submit_url(url, data):
    headers = {
            "Accept" : "application/json",
            "x-apikey" : config['vt']
    }
    print(f"submitting :{data}")
    response = requests.request("POST", url, headers=headers, data=data)
    return response

# Attempts to get file from hash using virus.exchange
async def get_file_share(hash):
    api_key = config['virus_share']
    url = f"https://virus.exchange/api/file/{hash}/download"

    headers = {
        'accept' : 'application/octet-stream',
        "Authorization" : f"Bearer {api_key}"
    }
    if os.path.exists(hash):
        return False
    else:
        response = requests.request("GET", url, headers=headers)
        if response.status_code != 200:
            return True
        with open(f"{hash}", "wb") as f:
            f.write(response.content)
        password = "infected"
        #zipf file with password
        pyminizip.compress(hash, None, f"{hash}.zip", password, 5)
        #delete leftover file
        os.remove(hash)

        

async def craft_embed(data, url):
    vt_data = data.json()["data"]['attributes']['last_analysis_stats']
    #get total number of scans
    total_scans = int(vt_data.get('harmless')) + int(vt_data.get('malicious')) + int(vt_data.get('suspicious')) + int(vt_data.get('undetected'))
    #calculate detection rate
    detection_rate = round(int(vt_data.get('malicious')) + int(vt_data.get('suspicious')) / total_scans, 2)
    #change embed color if we have detections
    if detection_rate > 0:
        color = Color.red()
    else:
        color = Color.blue()
        #craft embed and add fields
    embed = discord.Embed(
        title = "VirusTotal Detection Rates",
        color = color
    )
    embed.set_thumbnail(url="https://upload.wikimedia.org/wikipedia/commons/thumb/b/b7/VirusTotal_logo.svg/564px-VirusTotal_logo.svg.png")
    embed.add_field(name="Link:", value=f"https://www.virustotal.com/gui/url/{url}")
    embed.add_field(name="Harmless:", value=vt_data.get('harmless'))
    embed.add_field(name="Malicious:", value=vt_data.get('malicious'))
    embed.add_field(name="Suspicious:", value=vt_data.get('suspicious'))
    embed.add_field(name="Undetected:", value=vt_data.get('undetected'))
    embed.add_field(name="Total:", value=total_scans)
    embed.add_field(name="Detection Rate:", value=f"{detection_rate}%")
    datestring = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
    embed.set_footer(text=f"{datestring}")
    return embed

@bot.command(pass_context=True)
async def vt(ctx):
    normalized_url = ctx.message.content.split()
    base64Url = await get_url(normalized_url[1])
    url = f'https://www.virustotal.com/api/v3/urls/{base64Url}'
    response = await get_vt_url_info(url)
    
    try:
        response.json()["error"]
        if response.json()["error"]['code'] == 'NotFoundError':
            await ctx.send("Submitting this to VT")
            data = {'url': f"{normalized_url[1]}"}
            submitData = await submit_url("https://www.virustotal.com/api/v3/urls", data)
            await asyncio.sleep(20)
            #print(f"submit data: {submitData.text}")
            if submitData.json()["error"]["code"] == "InvalidArgumentError":
                await ctx.send(f"URL {normalized_url[1]} cannot be processed. Check for typos!")
                return
            await vt(ctx)
    except KeyError as e:
        try:
            if response.json()["error"]["code"] == "NotFoundError":
                await ctx.send("URL Not Found. Retrying...")
                await vt(ctx)
                #print(f"This exists! {response.text}")
        except:
            vt_data = response.json()['data']['attributes']['last_analysis_stats']
            total_scans = int(vt_data.get('harmless')) + int(vt_data.get('malicious')) + int(vt_data.get('suspicious')) + int(vt_data.get('undetected'))
            if total_scans == 0:
                #await ctx.send("VirusTotal is taking awhile to process this URL. Please wait. (This message will repeat)")
                await asyncio.sleep(20)
                await vt(ctx)
            else:
                embed = await craft_embed(response, base64Url)
                await ctx.send(embed=embed)
@bot.command(pass_context=True)
async def get_file(ctx):
    command = ctx.message.content.split()
    file_hash = command[1]
    help_commands = ['-h', '-help', '--help', '--h']
    if command[1] in help_commands:
        embed = discord.Embed(
            title = "Get File",
            color = Color.blue()
        )
        embed.set_thumbnail(url="https://cdn.discordapp.com/avatars/793737282242084864/b7caaa589062a2ee0b5abed526e4f6b2.webp?size=1024")
        embed.add_field(name="Information", value="Accepts a file hash and attempts to retrieve it from virus.exchange.", inline=False)
        embed.add_field(name="Command Format", value="`?get_file $FILE_HASH`", inline=False)
        embed.add_field(name="Supports", value="SHA1, SHA256, SHA512, and MD5")
        embed.add_field(name="Zip Password", value="`infected`")
        datestring = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
        embed.set_footer(text=f"{datestring}")
        await ctx.send(embed=embed)
    else:
        result = await get_file_share(file_hash)
        if result == False:
            #send zip
            await ctx.send(file=discord.File(rf'{file_hash}.zip'))
            #delete zip after sending
            os.remove(f"{file_hash}.zip")
            #await ctx.send("Test")
        elif result == True:
            await ctx.send("Not on Virus Exchange")
        else:
            #copy/paste for the lazy
            #note: only works for the mw samples channel in the csc server
            
            #await ctx.send("Test")
            data = await ctx.send(file=discord.File(rf'{file_hash}.zip'))
            discord_message_data = data.attachments[0]
            await ctx.send(f"Copy me\n\n```wget {discord_message_data.url}; unzip -P infected {file_hash}.zip```")
            os.remove(f"{file_hash}.zip")

#send message to logging channel when a message is deleted
@bot.event
async def on_message_delete(message):
    #set channel id for logging
    channel = bot.get_channel(int(config['debug']))
    embed = discord.Embed(
        title = "Message Deleted",
        color = Color.red() 
    )
    embed.add_field(name="User: ",value=message.author.mention)
    embed.add_field(name="Channel: ",value=message.channel.mention)
    embed.add_field(name="Message: ", value=message.content)
    embed.add_field(name="Date: ",value=message.created_at)
    await channel.send(embed=embed)


#send message to logging channel when a message is edited
@bot.event
async def on_message_edit(before, after):
    #need to add this check because of the way discord handles embeds
    if before.content == after.content:
        return
    #set channel id for logging
    channel = bot.get_channel(int(config['debug']))
    embed = discord.Embed(
        title = "Message Edited",
        color = Color.purple() 
    )
    embed.add_field(name="User: ",value=before.author.mention)
    embed.add_field(name="Before: ",value=before.content)
    embed.add_field(name="After: ",value=after.content)
    embed.add_field(name="Channel: ",value=after.channel.mention)
    embed.add_field(name="Date: ",value=after.created_at)
    await channel.send(embed=embed)


#send message to logging channel when a reaction is added to a message
@bot.event
async def on_reaction_add(reaction, user):
    #set channel id for logging
    channel = bot.get_channel(int(config['debug']))
    embed = discord.Embed(
        title = "Reaction Added",
        color = Color.purple() 
    )
    embed.add_field(name="User: ",value=user.mention)
    embed.add_field(name="Reaction: ",value=reaction.emoji)
    embed.add_field(name="Channel: ",value=reaction.message.channel)
    embed.add_field(name="Message: ",value=reaction.message.content)
    await channel.send(embed=embed)


#send message to logging channel when a user joins or leaves a voice channel
@bot.event
async def on_voice_state_update(member, before, after):
    #set channel id for logging
    channel = bot.get_channel(int(config['debug']))
    if before.channel is None and after.channel is not None:
        embed = discord.Embed(
            title = "User Joined Voice Channel",
            color = Color.blue() 
        )
        embed.add_field(name="User: ",value=member.mention)
        embed.add_field(name="Channel: ",value=after.channel)
        embed.add_field(name="Date: ",value=datetime.utcnow())
        await channel.send(embed=embed)
        #await channel.send(f"{member.mention} joined {after.channel.mention}")
    elif before.channel != after.channel:
        embed = discord.Embed(
            title = "User Left Voice Channel",
            color = Color.orange() 
        )
        embed.add_field(name="User: ",value=member.mention)
        embed.add_field(name="Channel: ",value=before.channel)
        embed.add_field(name="Date: ",value=datetime.utcnow())
        await channel.send(embed=embed)

#start the bot
bot.run(config['token'])
