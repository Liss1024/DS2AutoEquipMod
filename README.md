This is an attempt to make a auto-equip mod for Dark Souls 2: SoFT. I didn't succeed, so you are welcome to try and finish it! 
TLDR: It identifies all picked up items and has a hook function that triggers every time player picks up an item. But it still cannot equip that item, as I didn't manage to find how to do that.

How does it work:
1. Main idea is injecting a DLL after DS2 is already running. I've wrote a simple injector for it, you can find it in x64/Release folder, along with latest DLL.
2. In the DLL, we need to make a hook for a function that triggers whenever player picks up an item. I've succesfully did this part.
3. Then we need to equip new item, using ID received from first hook. I tried to just rewrite ID at addresses, where I think game stores equiped item IDs; I've used Cheat Engine and cheat table for DS2 for this. Sadly, this doesn't change equiped items; I have multiple theories why, but that's not really relevant.

 So the problem is to figure out how to make the game equip items. If you want to have a try at it - be my guest. 
 You can text me in Discord, if you need more details @Liss1024
