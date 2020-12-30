import discord #duhhhh
import asyncio 
import logging #used for useful logging output (and checking for heartbeat)
import json #used for parsing config.json to avoid keys being leaked to github
import aiohttp #used to make requests to various API endpoints
from removebg import RemoveBg #API wrapper for removebg.com 
from discord.ext import commands
#setup logging
logging.basicConfig(
    level = logging.INFO,
    format = '[%(levelname)s][%(asctime)s] - %(message)s',
    datefmt = '%Y-%m-%d %H:%M:%S',
)
#init bot
intents = discord.Intents.default()
bot = commands.Bot(command_prefix='?', intents=intents)
#get bot token from config.json
with open('config.json') as config_file:
    config = json.load(config_file)

@bot.event
async def on_ready():
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=f"{len(bot.guilds)} servers! with {len(bot.users)} users!"))
    print(f'Bot connected as {bot.user}')
	
@bot.event
async def on_message_delete(message):
    #set channel id for logging, eventually add this to config.json
    channel = bot.get_channel(786135681704788019)
    await channel.send(f"{message.author.mention} deleted the message: `{message.content}` in channel {message.channel.mention} at {message.created_at} UTC")


bot.run(config['token'])

