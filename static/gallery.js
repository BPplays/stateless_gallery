"use strict";

// ── Data (server-injected) ────────────────────────────────────────────────
var IMAGES = (function() {
	try {
		return JSON.parse(document.getElementById("gallery-data").textContent);
	} catch (e) {
		console.error("Failed to parse gallery data:", e);
		return [];
	}
})();

// ── Config ────────────────────────────────────────────────────────────────
//
// SIDE_SLOT_THUMBS
//   true  → Only one full-res image is ever in-flight at a time: the
//            centre slot. Side slots show the thumbnail immediately and
//            nothing else — no background full-res fetches, no preloading.
//            Full-res for the next image loads only after you navigate to it.
//            Best for metered connections or large image files.
//
//   false → Side slots load full-res eagerly in the background so swipe-to
//            is instant with no spinner. Uses more bandwidth since full-res
//            is fetched for images you may not end up viewing.
var SIDE_SLOT_THUMBS = true;

// ── DOM refs ──────────────────────────────────────────────────────────────
var gallery    = document.getElementById("gallery");
var lightbox   = document.getElementById("lightbox");
var lbTrack    = document.getElementById("lb-track");
var lbImgPrev  = document.getElementById("lb-img-prev");
var lbImgCurr  = document.getElementById("lb-img-curr");
var lbImgNext  = document.getElementById("lb-img-next");
var lbSpinner  = document.getElementById("lb-spinner");
var lbName     = document.getElementById("lb-name");
var lbCounter  = document.getElementById("lb-counter");
var countEl    = document.getElementById("js-count");
var reloadToast = document.getElementById("reload-toast");
var lbDownload = document.getElementById("lb-download");
var lbShare    = document.getElementById("lb-share");

// ── Grid ─────────────────────────────────────────────────────────────────
function buildGrid(images) {
	gallery.innerHTML = "";
	if (images.length === 0) {
		gallery.innerHTML = '<p class="empty">No images found. Check that <code>photo_dirs</code> in your config points to a directory with supported image files.</p>';
		return;
	}
	images.forEach(function (img, i) {
		var item  = document.createElement("div");
		item.className = "thumb-item";
		item.setAttribute("role", "listitem");
		item.setAttribute("tabindex", "0");
		item.setAttribute("aria-label", img.name);

		var el = document.createElement("img");
		el.src = img.thumb; el.alt = img.name;
		el.loading = "lazy"; el.decoding = "async";

		var label = document.createElement("div");
		label.className = "label";
		label.textContent = img.name;

		item.appendChild(el);
		item.appendChild(label);

		(function (idx) {
			function open() { openLightbox(idx); }
			item.addEventListener("mousedown", open);
			item.addEventListener("keydown", function (e) {
				if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); }
			});
		}(i));

		gallery.appendChild(item);
	});
}

// ── Image fetcher ─────────────────────────────────────────────────────────
//
// fetchImg(url, onDone, onFail)
//   Unified fetch+decode pipeline with request deduplication.
//   • Returns cached result immediately if available.
//   • Piggybacks callbacks onto an existing in-flight request for the same
//     URL rather than starting a duplicate network request.
//   • Always waits for onload before calling decode() — calling decode()
//     on an unloaded Image rejects immediately on iOS Safari, which would
//     cache a broken element.
var imgCache  = new Map(); // url → decoded Image element
var imgFlight = new Map(); // url → { img, cbs: [{onDone, onFail}] }

function fetchImg(url, onDone, onFail) {
	// Cache hit: return immediately.
	if (imgCache.has(url)) { onDone(imgCache.get(url)); return; }

	// In-flight: piggyback onto existing request.
	if (imgFlight.has(url)) {
		imgFlight.get(url).cbs.push({ onDone: onDone, onFail: onFail });
		return;
	}

	// New fetch.
	var img   = new Image();
	var entry = { img: img, cbs: [{ onDone: onDone, onFail: onFail }] };
	imgFlight.set(url, entry);

	img.onload = function () {
		imgFlight.delete(url);
		function settle() {
			imgCache.set(url, img);
			entry.cbs.forEach(function (cb) { cb.onDone(img); });
		}
		// decode() pre-warms the GPU texture so the image paints without
		// a compositor stall. Must be after onload (iOS Safari fix).
		if (typeof img.decode === "function") {
			img.decode().catch(function () {}).finally(settle);
		} else {
			settle();
		}
	};
	img.onerror = function () {
		imgFlight.delete(url);
		entry.cbs.forEach(function (cb) { cb.onFail(); });
	};
	img.src = url;
}

// Warm the cache without updating any slot.
function prefetch(url) { fetchImg(url, function () {}, function () {}); }

// Prefetch full-res for ±2 neighbors so rapid navigation is instant.
// When SIDE_SLOT_THUMBS is on, full-res is only ever loaded for the
// centre slot, so we skip prefetching here entirely.
function preloadAdjacent(index) {
	if (SIDE_SLOT_THUMBS) return;
	var n = IMAGES.length;
	if (n <= 1) return;
	for (var d = 1; d <= 2; d++) {
		prefetch(IMAGES[((index + d) % n + n) % n].full);
		prefetch(IMAGES[((index - d) % n + n) % n].full);
	}
}

// ── Centre slot loading ───────────────────────────────────────────────────
//
// Shows the thumbnail immediately (usually a near-instant HTTP cache hit
// since the grid already loaded it), then upgrades to full-res when decoded.
// The spinner indicates the full-res is still loading.
//
// loadGen is incremented each time a new centre load starts; async
// callbacks check their captured generation and bail if superseded.
var loadGen = 0;

function loadCentre(imgData) {
	var gen = ++loadGen;

	// Full-res already decoded and cached: display immediately, no spinner.
	if (imgCache.has(imgData.full)) {
		lbImgCurr.src = imgCache.get(imgData.full).src;
		lbImgCurr.alt = imgData.name;
		lbImgCurr.classList.remove("fading");
		lbSpinner.classList.remove("visible");
		return;
	}

	// Show thumbnail while full-res is fetching.
	// Avoid a redundant assignment if the slot already shows our thumbnail
	// (e.g. it just became centre from a side slot).
	var thumbAbs = new URL(imgData.thumb, location.href).href;
	if (lbImgCurr.src !== thumbAbs) {
		lbImgCurr.src = imgData.thumb;
		lbImgCurr.alt = imgData.name;
	}
	lbImgCurr.classList.remove("fading");
	lbSpinner.classList.add("visible");

	fetchImg(imgData.full,
		function (imgEl) {
			if (gen !== loadGen) return; // superseded
			lbImgCurr.src = imgEl.src;
			lbImgCurr.alt = imgData.name;
			lbSpinner.classList.remove("visible");
		},
		function () {
			if (gen !== loadGen) return;
			lbSpinner.classList.remove("visible");
		}
	);
}

// ── Side slot loading ─────────────────────────────────────────────────────
//
// Side slots always show the thumbnail immediately (no wait, no spinner).
// genRef is a {v: Number} object — incrementing genRef.v cancels any
// pending upgrade for this slot.
//
// When SIDE_SLOT_THUMBS = true:
//   Shows thumbnail only. No full-res fetch of any kind — not even a
//   background warm. Full-res is requested by loadCentre() only after
//   the user navigates to this slot.
//
// When SIDE_SLOT_THUMBS = false:
//   Also upgrades the slot src to full-res when the fetch completes,
//   so swipe-to is instant with no upgrade delay.

var prevGen = { v: 0 };
var nextGen = { v: 0 };

function loadSide(slotEl, genRef, imgData) {
	if (!imgData) { slotEl.src = ""; slotEl.alt = ""; return; }
	var gen = ++genRef.v;

	// Full-res already cached: show it directly (regardless of mode).
	if (imgCache.has(imgData.full)) {
		slotEl.src = imgCache.get(imgData.full).src;
		slotEl.alt = imgData.name;
		return;
	}

	// Show thumbnail immediately.
	slotEl.src = imgData.thumb;
	slotEl.alt = imgData.name;

	if (SIDE_SLOT_THUMBS) {
		// Thumb-only mode: show the thumbnail and do nothing else.
		// Full-res will be fetched by loadCentre() only when this slot
		// becomes the active centre — no background full-res fetches.
	} else {
		// Upgrade slot to full-res when decoded.
		var capturedEl  = slotEl;
		var capturedRef = genRef;
		var capturedGen = gen;
		fetchImg(imgData.full,
			function (imgEl) {
				if (capturedGen !== capturedRef.v) return; // slot was reassigned
				capturedEl.src = imgEl.src;
			},
			function () {}
		);
	}
}

// Populate all three slots for a given centre index.
// Side slots are deferred one rAF so centre gets first priority on
// network connections and decode resources.
function loadAllSlots(index) {
	var n = IMAGES.length;
	lbName.textContent    = IMAGES[index].name;
	lbCounter.textContent = "(" + (index + 1) + "\u202f/\u202f" + n + ")";

	loadCentre(IMAGES[index]);

	if (n > 1) {
		requestAnimationFrame(function () {
			loadSide(lbImgPrev, prevGen, IMAGES[(index - 1 + n) % n]);
			loadSide(lbImgNext, nextGen, IMAGES[(index + 1) % n]);
		});
	}
}

// ── URL hash deep-linking ─────────────────────────────────────────────────
function setHashForIndex(index) {
	var name = IMAGES[index] ? IMAGES[index].name : "";
	if (name) history.replaceState(null, "", "#" + encodeURIComponent(name));
}
function clearHash() {
	history.replaceState(null, "", location.pathname + location.search);
}
function indexFromHash() {
	var hash = decodeURIComponent(location.hash.slice(1));
	if (!hash) return -1;
	return IMAGES.findIndex(function (img) { return img.name === hash; });
}

// ── Lightbox state ────────────────────────────────────────────────────────
var current = 0;

function isLightboxOpen() {
	return lightbox.classList.contains("open")
}

function updateTopbar(index) {
	var img = IMAGES[index];
	if (!img) return;
	lbDownload.href = img.full;
	lbDownload.setAttribute("download", img.name);
}

function openLightbox(index) {
	current = index;
	lightbox.classList.add("open");
	document.body.style.overflow = "hidden";
	loadAllSlots(current);
	setHashForIndex(current);
	updateTopbar(current);
	preloadAdjacent(current);
	showButtons();
}

function closeLightbox() {
	lightbox.classList.remove("open");
	document.body.style.overflow = "";
	clearHash();
	loadGen++; // cancel any in-flight centre-slot load
	lbSpinner.classList.remove("visible");
	lbImgCurr.classList.remove("fading");

	showButtons();
	exitFullscreen()
}

function navigate(delta) {
	if (IMAGES.length === 0 || swipeAnimating) return;
	commitSwipe(delta);
}


// ── Browser back/forward ──────────────────────────────────────────────────
window.addEventListener("hashchange", function () {
	var i = indexFromHash();
	if (i >= 0) {
		if (!lightbox.classList.contains("open")) {
			openLightbox(i);
		} else {
			current = i;
			loadAllSlots(i);
			updateTopbar(i);
			preloadAdjacent(i);
		}
	} else if (lightbox.classList.contains("open")) {
		lightbox.classList.remove("open");
		document.body.style.overflow = "";
		loadGen++;
	}
});

// ── Button controls ───────────────────────────────────────────────────────
document.getElementById("lb-prev").addEventListener("mousedown", function () {
	navigate(-1);
});
document.getElementById("lb-next").addEventListener("mousedown", function () {
	navigate(1);
});
document.getElementById("lb-close").addEventListener("mousedown", function () {
	closeLightbox()
});

lightbox.addEventListener("mousedown", function (e) {
	var t = e.target;
	if (t === lightbox || t.id === "lb-stage" || t.id === "lb-track" || t.classList.contains("lb-slide")) {
		closeLightbox();
	}
});

// ── Keyboard ──────────────────────────────────────────────────────────────
document.addEventListener("keydown", function (e) {
	if (!lightbox.classList.contains("open")) return;
	if (e.key === "Escape")                                   closeLightbox();
	if (e.key === "ArrowLeft"  || e.key === "h" || e.key === "a") navigate(-1);
	if (e.key === "ArrowRight" || e.key === "l" || e.key === "d") navigate(1);
	if (e.key === "f") toggleFullscreen();
});

// ── Touch / swipe ─────────────────────────────────────────────────────────
var touchStartX = 0, touchStartY = 0, touchStartTime = 0;
var dragActive    = false;
var swipeAnimating = false;
var SWIPE_MIN_DIST  = 30;   // px
var SWIPE_MIN_VEL   = 0.2;  // px/ms
var SWIPE_AXIS_LOCK = 1.5;
var ANIM_MS         = 280;

function setTrackX(extraPx) {
	lbTrack.style.transform = extraPx === 0
		? "translateX(-33.333%)"
		: "translateX(calc(-33.333% + " + extraPx + "px))";
}

lightbox.addEventListener("touchstart", function (e) {
	if (swipeAnimating || e.touches.length !== 1) return;
	if (e.target.closest("#lb-topbar") || e.target.closest("#lb-caption") || e.target.closest("#lb-fullscreen")) return;
	touchStartX    = e.touches[0].clientX;
	touchStartY    = e.touches[0].clientY;
	touchStartTime = Date.now();
	dragActive     = true;
	lbTrack.style.willChange  = "transform";
	lbTrack.style.transition  = "none";
}, { passive: true });

	lightbox.addEventListener("touchmove", function (e) {
		if (!dragActive || e.touches.length !== 1) return;
		var dx = e.touches[0].clientX - touchStartX;
		var dy = e.touches[0].clientY - touchStartY;
		if (Math.abs(dy) > Math.abs(dx) * SWIPE_AXIS_LOCK && Math.abs(dy) > 10) {
			dragActive = false;
			lbTrack.style.willChange = "";
			lbTrack.style.transition = "";
			setTrackX(0);
			return;
		}

		// Prevent swiping when zoomed in (if element is scaled)
		if (e.target.style.transform && e.target.style.transform !== "none") {
			return;
		}

		if (IMAGES.length > 1) setTrackX(dx);
	}, { passive: true });

lightbox.addEventListener("touchend", function (e) {
	if (!dragActive) return;
	dragActive = false;
	var dx      = e.changedTouches[0].clientX - touchStartX;
	var dy      = e.changedTouches[0].clientY - touchStartY;
	var elapsed = Date.now() - touchStartTime;
	var vel     = Math.abs(dx) / elapsed;
	var isHoriz = Math.abs(dx) > Math.abs(dy) * SWIPE_AXIS_LOCK;
	var isSwipe = isHoriz && (Math.abs(dx) > SWIPE_MIN_DIST || vel > SWIPE_MIN_VEL);
	if (isSwipe && IMAGES.length > 1) {
		commitSwipe(dx < 0 ? 1 : -1);
	} else {
		lbTrack.style.transition = "transform " + ANIM_MS + "ms cubic-bezier(.25,.46,.45,.94)";
		setTrackX(0);
		setTimeout(function () { lbTrack.style.transition = ""; lbTrack.style.willChange = ""; }, ANIM_MS + 10);
	}
}, { passive: true });

lightbox.addEventListener("touchcancel", function () {
	if (!dragActive) return;
	dragActive = false;
	lbTrack.style.transition = "transform " + ANIM_MS + "ms cubic-bezier(.25,.46,.45,.94)";
	setTrackX(0);
	setTimeout(function () { lbTrack.style.transition = ""; lbTrack.style.willChange = ""; }, ANIM_MS + 10);
}, { passive: true });

function isFullscreen() {
	if (!document.fullscreenElement && !document.webkitFullscreenElement) {
		return false
	}

	return true
}

function toggleFullscreen() {
	if (!isFullscreen()) {
		enterFullscreen()
	} else {
		exitFullscreen()
	}

}

function enterFullscreen() {
	if (isFullscreen()) {
		return
	}

	if (lightbox.requestFullscreen)            lightbox.requestFullscreen();
	else if (lightbox.webkitRequestFullscreen) lightbox.webkitRequestFullscreen();

}

function exitFullscreen() {
	if (!isFullscreen()) {
		return
	}

	if (document.exitFullscreen)              document.exitFullscreen();
	else if (document.webkitExitFullscreen)   document.webkitExitFullscreen();
}

// ── Swipe commit ──────────────────────────────────────────────────────────
//
// Animates the track to the arriving slot, then reshuffles the three img
// srcs so we can snap back to the centre without any network hit.
// After the reshuffle:
//   • loadCentre() upgrades the new centre slot to full-res (instant if
//     preloading worked; otherwise shows thumb with spinner).
//   • loadSide() populates the newly vacated far slot.
function commitSwipe(direction) {
	swipeAnimating = true;
	var n = IMAGES.length;

	lbTrack.style.willChange = "transform";
	lbTrack.style.transition = "transform " + ANIM_MS + "ms cubic-bezier(.25,.46,.45,.94)";
	lbTrack.style.transform  = direction > 0 ? "translateX(-66.666%)" : "translateX(0%)";

	setTimeout(function () {
		current = ((current + direction) % n + n) % n;
		lbTrack.style.transition = "none";

		// Reshuffle slot srcs. The arriving slot src (thumb or full-res)
		// becomes the new centre src; the vacated slot is cleared.
		if (direction > 0) {
			lbImgPrev.src = lbImgCurr.src;  lbImgPrev.alt = lbImgCurr.alt;
			lbImgCurr.src = lbImgNext.src;  lbImgCurr.alt = lbImgNext.alt;
			lbImgNext.src = "";              lbImgNext.alt = "";
		} else {
			lbImgNext.src = lbImgCurr.src;  lbImgNext.alt = lbImgCurr.alt;
			lbImgCurr.src = lbImgPrev.src;  lbImgCurr.alt = lbImgPrev.alt;
			lbImgPrev.src = "";              lbImgPrev.alt = "";
		}

		setTrackX(0);

		lbName.textContent    = IMAGES[current].name;
		lbCounter.textContent = "(" + (current + 1) + "\u202f/\u202f" + n + ")";
		setHashForIndex(current);
		updateTopbar(current);

		// Upgrade the new centre slot to full-res.
		// This is usually instant when preloading has run ahead.
		loadCentre(IMAGES[current]);

		requestAnimationFrame(function () {
			lbTrack.style.transition = "";
			lbTrack.style.willChange = "";
			swipeAnimating = false;
		});

		// Load the newly vacated far slot and extend the preload window,
		// deferred until idle to avoid competing with the repaint.
		var farSlotEl  = direction > 0 ? lbImgNext : lbImgPrev;
		var farSlotGen = direction > 0 ? nextGen   : prevGen;
		var farIdx     = direction > 0 ? (current + 1) % n : (current - 1 + n) % n;

		var doIdle = function () {
			loadSide(farSlotEl, farSlotGen, IMAGES[farIdx]);
			preloadAdjacent(current);
		};
		if (typeof requestIdleCallback === "function") {
			requestIdleCallback(doIdle, { timeout: 500 });
		} else {
			setTimeout(doIdle, 100);
		}
	}, ANIM_MS + 10);
}

// ── Fullscreen ────────────────────────────────────────────────────────────
(function () {
	var btn      = document.getElementById("lb-fullscreen");
	var iconEnter = document.getElementById("lb-fs-enter");
	var iconExit  = document.getElementById("lb-fs-exit");

	if (!document.fullscreenEnabled && !document.webkitFullscreenEnabled) {
		btn.classList.add("unsupported");
		return;
	}

	btn.addEventListener("mousedown", function (e) {
		e.stopPropagation();
		toggleFullscreen();
	});

	function onFsChange() {
		var active = !!(document.fullscreenElement || document.webkitFullscreenElement);
		iconEnter.style.display = active ? "none" : "";
		iconExit.style.display  = active ? ""     : "none";
		btn.setAttribute("aria-label", active ? "Exit fullscreen" : "Toggle fullscreen");
	}
	document.addEventListener("fullscreenchange",       onFsChange);
	document.addEventListener("webkitfullscreenchange", onFsChange);
}());

// ── Share / copy helpers ──────────────────────────────────────────────────
function copyToClipboard(text, onSuccess) {
	if (navigator.clipboard && navigator.clipboard.writeText) {
		navigator.clipboard.writeText(text).then(onSuccess).catch(function () {
			fallbackCopy(text, onSuccess);
		});
	} else {
		fallbackCopy(text, onSuccess);
	}
}
function fallbackCopy(text, onSuccess) {
	try {
		var tmp = document.createElement("input");
		tmp.value = text;
		document.body.appendChild(tmp);
		tmp.select();
		document.execCommand("copy");
		document.body.removeChild(tmp);
		onSuccess();
	} catch (e) {}
}

// ── Share button ──────────────────────────────────────────────────────────
lbShare.addEventListener("mousedown", function (e) {
	e.stopPropagation();
	var img = IMAGES[current];
	if (!img) return;
	var url = location.href;
	if (navigator.share) {
		navigator.share({ title: img.name, url: url }).catch(function () {});
		return;
	}
	copyToClipboard(url, function () {
		lbShare.classList.add("active");
		setTimeout(function () { lbShare.classList.remove("active"); }, 1800);
	});
});

// ── Download button ───────────────────────────────────────────────────────
lbDownload.addEventListener("mousedown", function (e) { e.stopPropagation(); });

// ── Copy-link button ──────────────────────────────────────────────────────
document.getElementById("lb-copy").addEventListener("mousedown", function (e) {
	e.stopPropagation();
	var btn = this;
	copyToClipboard(location.href, function () {
		btn.classList.add("copied");
		setTimeout(function () { btn.classList.remove("copied"); }, 1800);
	});
});

// ── Hot-reload polling ────────────────────────────────────────────────────
// Polls the page every 10 s and rebuilds the grid if the image count changed.
(function () {
	var INTERVAL = 10000;
	function poll() {
		fetch(location.href, { cache: "no-store" })
			.then(function (r) { return r.text(); })
			.then(function (html) {
				var match = html.match(/var IMAGES = (\[[\s\S]*?\]);/);
				if (!match) return;
				var fresh;
				try { fresh = JSON.parse(match[1]); } catch (e) { return; }
				if (fresh.length === IMAGES.length) return;
				var delta = fresh.length - IMAGES.length;
				var msg = delta > 0
					? "+" + delta + " new photo" + (delta === 1 ? "" : "s")
					: Math.abs(delta) + " photo" + (Math.abs(delta) === 1 ? "" : "s") + " removed";
				IMAGES = fresh;
				buildGrid(IMAGES);
				countEl.textContent = fresh.length + " photo" + (fresh.length === 1 ? "" : "s");
				if (lightbox.classList.contains("open") && current >= IMAGES.length) closeLightbox();
				reloadToast.textContent = msg;
				reloadToast.classList.add("show");
				setTimeout(function () { reloadToast.classList.remove("show"); }, 3000);
			})
			.catch(function () {});
	}
	setInterval(poll, INTERVAL);
}());

// ── Auto-hide buttons after inactivity ────────────────────────────────────
var hideTimeout;
var showButtons = function() {
	// Show all buttons
	document.getElementById("lb-fullscreen").style.opacity = "1";
	document.getElementById("lb-topbar").style.opacity = "1";
	document.getElementById("lb-prev").style.opacity = "1";
	document.getElementById("lb-next").style.opacity = "1";
	document.body.style.cursor = "";

	// disable always
	document.getElementById("lb-caption").style.opacity = "0";

	// Clear any existing timeout
	clearTimeout(hideTimeout);

	// Set new timeout to hide buttons after 3 seconds
	if (isLightboxOpen()) {
		hideTimeout = setTimeout(function() {
			document.getElementById("lb-fullscreen").style.opacity = "0";
			document.getElementById("lb-topbar").style.opacity = "0";
			document.getElementById("lb-prev").style.opacity = "0";
			document.getElementById("lb-next").style.opacity = "0";
			document.getElementById("lb-caption").style.opacity = "0";

			document.body.style.cursor = "none";
		}, 3000);
	} else {
		hideTimeout = null
	}
};

document.addEventListener("mousemove", showButtons);
document.addEventListener("touchmove", showButtons);
document.addEventListener("mousedown", showButtons);
document.addEventListener("touchstart", showButtons);
document.addEventListener("keydown", showButtons);



// ── Settings management ──────────────────────────────────────────────
var settings = {
	primary: '#ff66cc',
	secondary: '#0099ff'
};

function loadSettings() {
	var savedSettings = localStorage.getItem('gallerySettings');
	if (savedSettings) {
		try {
			var parsed = JSON.parse(savedSettings);
			// Apply any valid settings we have, reset invalid ones to default
			if (parsed.primary && isValidColor(parsed.primary)) {
				settings.primary = parsed.primary;
			} else {
				console.log("resetting primary color, not valid or not there")
				settings.primary = '#ff66cc';
			}

			if (parsed.secondary && isValidColor(parsed.secondary)) {
				settings.secondary = parsed.secondary;
			} else {
				settings.secondary = '#0099ff';
			}

			applySettings();
		} catch (e) {
			// If parsing fails, use defaults
			applySettings();
		}
	} else {
		// Apply default settings if none saved
		applySettings();
	}
}

function isValidColor(color) {
	return true
	// Basic color validation
	return /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/.test(color);
}

function applySettings() {
	// Apply CSS variables to root
	document.documentElement.style.setProperty('--primary', settings.primary);
	document.documentElement.style.setProperty('--secondary', settings.secondary);

	// Update dropdown values
	var primarySelect = document.getElementById('primary-color');
	var secondarySelect = document.getElementById('secondary-color');
	if (primarySelect && secondarySelect) {
		primarySelect.value = settings.primary;
		secondarySelect.value = settings.secondary;
	}
}

function exportSettings() {
	var settingsToExport = {
		primary: settings.primary,
		secondary: settings.secondary
	};

	var blob = new Blob([JSON.stringify(settingsToExport, null, 2)], {type: 'application/json'});
	var url = URL.createObjectURL(blob);

	var a = document.createElement('a');
	a.href = url;
	a.download = 'gallery-settings.json';
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	URL.revokeObjectURL(url);
}

function importSettings() {
	var input = document.createElement('input');
	input.type = 'file';
	input.accept = '.json';

	input.onchange = function(e) {
		var file = e.target.files[0];
		if (!file) return;

		var reader = new FileReader();
		reader.onload = function(e) {
			try {
				var importedSettings = JSON.parse(e.target.result);
				var validSettings = {
					primary: settings.primary,
					secondary: settings.secondary
				};

				if (importedSettings.primary && isValidColor(importedSettings.primary)) {
					validSettings.primary = importedSettings.primary;
				}

				if (importedSettings.secondary && isValidColor(importedSettings.secondary)) {
					validSettings.secondary = importedSettings.secondary;
				}

				// Update settings and apply them
				settings = validSettings;
				applySettings();
				localStorage.setItem('gallerySettings', JSON.stringify(settings));

				// Show notification
				showToast('Settings imported successfully');
			} catch (error) {
				showToast('Error importing settings');
			}
		};
		reader.readAsText(file);
	};

	input.click();
}

function showToast(message) {
	var toast = document.getElementById('reload-toast');
	if (toast) {
		toast.textContent = message;
		toast.classList.add('show');
		setTimeout(function() {
			toast.classList.remove('show');
		}, 3000);
	}
}

// ── Settings management ──────────────────────────────────────────────
var settings = {
	primary: 'var(--blue)',
	secondary: 'var(--green)'
};

function loadSettings() {
	var savedSettings = localStorage.getItem('gallerySettings');
	if (savedSettings) {
		try {
			var parsed = JSON.parse(savedSettings);
			// Apply any valid settings we have, reset invalid ones to default
			if (parsed.primary && isValidColor(parsed.primary)) {
				settings.primary = parsed.primary;
			} else {
				settings.primary = 'var(--blue)';
			}

			if (parsed.secondary && isValidColor(parsed.secondary)) {
				settings.secondary = parsed.secondary;
			} else {
				settings.secondary = 'var(--green)';
			}

			applySettings();
		} catch (e) {
			// If parsing fails, use defaults
			applySettings();
		}
	} else {
		// Apply default settings if none saved
		applySettings();
	}
}

function isValidColor(color) {
	// Basic color validation
	return /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/.test(color);
}

function applySettings() {
	// Apply CSS variables to root
	document.documentElement.style.setProperty('--primary', settings.primary);
	document.documentElement.style.setProperty('--secondary', settings.secondary);

	// Update selected color indicators
	updateColorIndicators();
}

function updateColorIndicators() {
	// Remove selected class from all color options
	var primaryOptions = document.querySelectorAll('#primary-color-options div');
	var secondaryOptions = document.querySelectorAll('#secondary-color-options div');

	primaryOptions.forEach(function(option) {
		option.classList.remove('selected');
		if (option.getAttribute('data-color') === settings.primary) {
			option.classList.add('selected');
		}
	});

	secondaryOptions.forEach(function(option) {
		option.classList.remove('selected');
		if (option.getAttribute('data-color') === settings.secondary) {
			option.classList.add('selected');
		}
	});
}

function exportSettings() {
	var settingsToExport = {
		primary: settings.primary,
		secondary: settings.secondary
	};

	var blob = new Blob([JSON.stringify(settingsToExport, null, 2)], {type: 'application/json'});
	var url = URL.createObjectURL(blob);

	var a = document.createElement('a');
	a.href = url;
	a.download = 'gallery-settings.json';
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	URL.revokeObjectURL(url);
}

function importSettings() {
	var input = document.createElement('input');
	input.type = 'file';
	input.accept = '.json';

	input.onchange = function(e) {
		var file = e.target.files[0];
		if (!file) return;

		var reader = new FileReader();
		reader.onload = function(e) {
			try {
				var importedSettings = JSON.parse(e.target.result);
				var validSettings = {
					primary: settings.primary,
					secondary: settings.secondary
				};

				if (importedSettings.primary && isValidColor(importedSettings.primary)) {
					validSettings.primary = importedSettings.primary;
				}

				if (importedSettings.secondary && isValidColor(importedSettings.secondary)) {
					validSettings.secondary = importedSettings.secondary;
				}

				// Update settings and apply them
				settings = validSettings;
				applySettings();
				localStorage.setItem('gallerySettings', JSON.stringify(settings));

				// Show notification
				showToast('Settings imported successfully');
			} catch (error) {
				showToast('Error importing settings');
			}
		};
		reader.readAsText(file);
	};

	input.click();
}

function showToast(message) {
	var toast = document.getElementById('reload-toast');
	if (toast) {
		toast.textContent = message;
		toast.classList.add('show');
		setTimeout(function() {
			toast.classList.remove('show');
		}, 3000);
	}
}

// ── Open from hash on page load ───────────────────────────────────────────
(function () {
	// Load settings before building grid
	loadSettings();

	var i = indexFromHash();
	if (i >= 0) {
		openLightbox(i);
		// Defer grid build so it doesn't compete with the LCP image fetch.
		if (typeof requestIdleCallback === "function") {
			requestIdleCallback(function () { buildGrid(IMAGES); }, { timeout: 2000 });
		} else {
			setTimeout(function () { buildGrid(IMAGES); }, 200);
		}
	} else {
		buildGrid(IMAGES);
	}
}());

// ── Settings UI handling ──────────────────────────────────────────────
(function() {
	// Settings button event
	var settingsBtn = document.getElementById('settings-btn');
	var settingsPanel = document.getElementById('settings-panel');
	var closeSettingsBtn = document.getElementById('close-settings');
	var exportSettingsBtn = document.getElementById('export-settings');
	var importSettingsBtn = document.getElementById('import-settings');
	var primaryOptions = document.querySelectorAll('#primary-color-options div');
	var secondaryOptions = document.querySelectorAll('#secondary-color-options div');

	if (settingsBtn && settingsPanel) {
		settingsBtn.addEventListener('click', function() {
			settingsPanel.style.display = 'block';
			updateColorIndicators();
		});

		closeSettingsBtn.addEventListener('click', function() {
			settingsPanel.style.display = 'none';
		});

		exportSettingsBtn.addEventListener('click', exportSettings);
		importSettingsBtn.addEventListener('click', importSettings);

		// Add event listeners to color options
		primaryOptions.forEach(function(option) {
			option.addEventListener('click', function() {
				settings.primary = this.getAttribute('data-color');
				applySettings();
				localStorage.setItem('gallerySettings', JSON.stringify(settings));
			});
		});

		secondaryOptions.forEach(function(option) {
			option.addEventListener('click', function() {
				settings.secondary = this.getAttribute('data-color');
				applySettings();
				localStorage.setItem('gallerySettings', JSON.stringify(settings));
			});
		});
	}
})();

document.querySelectorAll("[data-color]").forEach(el => {
	el.style.backgroundColor = el.dataset.color;
});
