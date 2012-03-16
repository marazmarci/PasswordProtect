package de.xghostkillerx.passwordprotect;

import org.bukkit.ChatColor;
import org.bukkit.Location;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.entity.Player;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;

public class PasswordProtectPlayerListener implements Listener {
	public PasswordProtect plugin;
	public PasswordProtectPlayerListener(PasswordProtect instance) {
		plugin = instance;
	}

	// When the player joins, force a password and check permissions
	@EventHandler(priority = EventPriority.HIGHEST)
	public void onPlayerJoin(final PlayerJoinEvent event) {
		Player player = event.getPlayer();
		if (this.plugin.getPassword() == null) {
			if (player.hasPermission("passwordprotect.setpassword")) {
				player.sendMessage(ChatColor.YELLOW + "PasswordProtect is enabled but no password has been set");
				player.sendMessage(ChatColor.YELLOW + "Use " + ChatColor.GREEN + "/setpassword " + ChatColor.RED + "<password>" + ChatColor.YELLOW + " to set it");
			}
		} else if (!player.hasPermission("passwordprotect.nopassword")) {
			sendToJail(player);
			plugin.jailedPlayers.add(player);
		}
	}

	public void stayInJail(Player player) {
		JailLocation jailLocation = plugin.getJailLocation(player);
		Location playerLocation = player.getLocation();

		int radius = jailLocation.getRadius();

		// If player is within radius^2 blocks of jail location...
		if (Math.abs(jailLocation.getBlockX() - playerLocation.getBlockX()) <= radius
				&& Math.abs(jailLocation.getBlockY() - playerLocation.getBlockY()) <= radius
				&& Math.abs(jailLocation.getBlockZ() - playerLocation.getBlockZ()) <= radius) {
			return;
		}

		sendToJail(player);
	}

	public void sendToJail(Player player) {
		JailLocation jailLocation = plugin.getJailLocation(player);
		player.teleport(jailLocation);
		sendPasswordRequiredMessage(player);
	}

	public void sendPasswordRequiredMessage(Player player) {
		player.sendMessage(ChatColor.YELLOW + "This server is password-protected");
		player.sendMessage(ChatColor.YELLOW + "Enter the password with " + ChatColor.GREEN + "/password " + ChatColor.RED + " <password>" + ChatColor.YELLOW + " to play");
	}

	@EventHandler(priority = EventPriority.HIGHEST)
	public void onPlayerMove(final PlayerMoveEvent event) {
		if (event.isCancelled()) {
			return;
		}

		Player player = event.getPlayer();
		if (plugin.jailedPlayers.contains(player)) {
			stayInJail(player);
			//event.setCancelled(true);
		}
	}

	@EventHandler(priority = EventPriority.HIGHEST)
	public void onPlayerInteract(final PlayerInteractEvent event) {
		if (event.isCancelled()) {
			return;
		}

		Player player = event.getPlayer();
		if (plugin.jailedPlayers.contains(player)) {
			event.setCancelled(true);
		}
	}

	@EventHandler(priority = EventPriority.HIGHEST)
	public void onPlayerDropItem(final PlayerDropItemEvent event) {
		if (event.isCancelled()) {
			return;
		}

		Player player = event.getPlayer();
		if (plugin.jailedPlayers.contains(player)) {
			event.setCancelled(true);
		}
	}

	@EventHandler(priority = EventPriority.HIGHEST)
	public void onPlayerCommandPreprocess(final PlayerCommandPreprocessEvent event) {
		Player player = event.getPlayer();
		String message = event.getMessage();

		if (plugin.jailedPlayers.contains(player)) {
			if (message.startsWith("/password")) {
				String password = message.replaceFirst("\\/password ", "");

				if (password.equals(plugin.getPassword())) {
					player.sendMessage(ChatColor.GREEN + "Server password accepted, you can now play");
					plugin.jailedPlayers.remove(player);
				}
				else {
					player.sendMessage(ChatColor.RED + "Server password incorrect, try again");
				}
			}
			else if (message.startsWith("/rules") || message.startsWith("/help")) {
				
			}
			else {
				sendPasswordRequiredMessage(player);
			}
			event.setCancelled(true);
		}
	}
}