from time import sleep
import discord #duhhhh
import logging #used for useful logging output (and checking for heartbeat)
import json #used for parsing config.json to avoid keys being leaked to github
from discord import channel
from discord.colour import Color #used to make requests to various API endpoints
from discord.ext import commands
from datetime import datetime
import requests
import hashlib
import base64
from urllib.parse import urlparse
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

@bot.command(pass_context=True)
async def vt(ctx):
    normalized_url = ctx.message.content.split()
    base64Url = await get_url(normalized_url[1])
    url = f'https://www.virustotal.com/api/v3/urls/{base64Url}'
    response = await get_vt_url_info(url)
    #try to get data, if errors means either:
    #1. VT hasnt seen this URL or
    #2. URL isnt valid
    try:
        #get last analysis stats if we've seen the URL before
        vt_data = response.json()['data']['attributes']['last_analysis_stats']
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
        embed.set_image(url="https://upload.wikimedia.org/wikipedia/commons/thumb/b/b7/VirusTotal_logo.svg/564px-VirusTotal_logo.svg.png")
        embed.add_field(name="Link:", value=f"https://www.virustotal.com/gui/url/{base64Url}")
        embed.add_field(name="Harmless:", value=vt_data.get('harmless'))
        embed.add_field(name="Malicious:", value=vt_data.get('malicious'))
        embed.add_field(name="Suspicious:", value=vt_data.get('suspicious'))
        embed.add_field(name="Undetected:", value=vt_data.get('undetected'))
        embed.add_field(name="Total:", value=total_scans)
        embed.add_field(name="Detection Rate:", value=f"{detection_rate}%")
        await ctx.send(embed=embed)
    except KeyError as e:
        await ctx.send(f"VirusTotal has not seen this URL. Submitting it now... please wait.")
        vt_url = f"https://www.virustotal.com/api/v3/urls"
        data = {'url': normalized_url[1]}
        submitData = await submit_url(vt_url, data)
        sleep(20)
        print(submitData.text)
        try:
            if submitData.json()['error']['code'] == "InvalidArgumentError":
                await ctx.send(f"Virustotal cannot process this URL! Check for typos! Reason: `{submitData.json()['error']['message']}`")
                return
            else:
                await ctx.send(f"{ctx.author.mention} Analysis Complete!")
                await vt(ctx)
        except KeyError:
            await ctx.send(f"{ctx.author.mention} Analysis Complete!")
            await vt(ctx)

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