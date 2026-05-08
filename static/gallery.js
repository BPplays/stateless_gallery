// ── Auto-hide buttons after inactivity ────────────────────────────────────
var hideTimeout;
var showButtons = function() {
	// Show all buttons
	document.getElementById("lb-fullscreen").style.opacity = "1";
	document.getElementById("lb-topbar").style.opacity = "1";
	document.getElementById("lb-prev").style.opacity = "1";
	document.getElementById("lb-next").style.opacity = "1";
	document.getElementById("lb-caption").style.opacity = "1";
	
	// Clear any existing timeout
	clearTimeout(hideTimeout);
	
	// Set new timeout to hide buttons after 3 seconds
	hideTimeout = setTimeout(function() {
		document.getElementById("lb-fullscreen").style.opacity = "0";
		document.getElementById("lb-topbar").style.opacity = "0";
		document.getElementById("lb-prev").style.opacity = "0";
		document.getElementById("lb-next").style.opacity = "0";
		document.getElementById("lb-caption").style.opacity = "0";
	}, 3000);
};

// Initialize with buttons visible
showButtons();

// Add event listeners to show buttons on user activity
document.addEventListener("mousemove", showButtons);
document.addEventListener("touchmove", showButtons);
document.addEventListener("mousedown", showButtons);
document.addEventListener("touchstart", showButtons);
document.addEventListener("keydown", showButtons);