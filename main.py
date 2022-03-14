import discord #duhhhh
import logging #used for useful logging output (and checking for heartbeat)
import json #used for parsing config.json to avoid keys being leaked to github
from discord import channel
from discord.colour import Color #used to make requests to various API endpoints
from discord.ext import commands
from datetime import datetime

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

@bot.command(pass_context=True)
async def pfp(ctx):
    try:
        pfp = ctx.message.mentions[0].avatar_url
        embed=discord.Embed(title=f"{ctx.message.mentions[0]}'s avatar", color=Color.green())
        embed.set_image(url=(pfp))
        await ctx.send(embed=embed)
    except IndexError:
        await ctx.send("You must mention a user!")

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

