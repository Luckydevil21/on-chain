"""
====================================================================
 THREAT INTEL DASHBOARD - One-Click Launcher for Your CTI Scripts
====================================================================

WHAT THIS PROGRAM DOES (plain English):
This opens a simple desktop window with one button for each of your
scripts:
    - Wallet Watcher       (checks flagged wallets for movement)
    - Victim Collator      (counts victims of one flagged wallet)
    - Crypto Address Watcher (scans blogs/Telegram for new addresses)
    - Link Tracer          (traces a victim wallet forward to see if
                             it links to a flagged illicit wallet)

Click a button, and that script runs in the background while its
output streams live into the panel below - no terminal typing
required. Any 🚨 ALERT lines are automatically highlighted in red so
they're impossible to miss. There's also a button to instantly open
the Excel report folder once a scan finishes.

HOW TO SET THIS UP (one-time only, no coding knowledge needed):

STEP 1 - Make sure Python is installed (you'll already have done
    this if you've run the other scripts). No extra libraries are
    needed for this dashboard itself - it only uses parts of Python
    that are already built in.

STEP 2 - Put this file in the SAME FOLDER as your scripts:
        wallet_watcher.py
        victim_collator.py
        crypto_address_watcher.py
        link_tracer.py
        threat_intel_dashboard.py   <- this file

    (They must all sit together in one folder for the buttons to
    find them.)

STEP 3 - Run this file ONE TIME from your terminal:

        python threat_intel_dashboard.py

    A window will open. From now on, everything happens by clicking
    buttons in that window - you will not need to type any more
    commands.

    TIP: On Windows, you can right-click this file later and choose
    "Open with > Python" to launch it without using the terminal at
    all. On Mac, you can do something similar via Automator, or just
    keep using the one terminal command above - it's quick either way.
====================================================================
"""

# ---- Everything below is part of Python's standard library.
# ---- Nothing extra needs to be installed for this dashboard itself. ----
import tkinter as tk
from tkinter import scrolledtext, messagebox
import subprocess
import threading
import queue
import sys
import os
import json
import platform
import webbrowser
import glob


# ====================================================================
# SECTION 1: SETTINGS YOU CAN EDIT
# ====================================================================

# --------------------------------------------------------------
# Each entry below is one button: a display name, the script file
# it runs, and a short description shown under the button. To add
# a new script later, just add another entry in this same format.
# --------------------------------------------------------------

# --------------------------------------------------------------
# "wallet_input" tells the dashboard what kind of address box to
# show above a script's button, and how to pass what's typed there
# through to the script:
#   "multi"  -> a box for one or more addresses (comma or space
#               separated), passed straight through. Leave blank to
#               fall back to that script's own built-in example list.
#   "single" -> a box for exactly one target address. Leave blank to
#               fall back to that script's own built-in example.
#   None     -> no address box shown (script doesn't take a wallet).
# --------------------------------------------------------------
SCRIPTS = [
    {
        "label": "🔍 Wallet Watcher",
        "filename": "wallet_watcher.py",
        "description": "Checks flagged wallets (ETH/BTC/XRP) for movement. Auto-includes anything Crypto Address Watcher has found.",
        "wallet_input": "multi",
        "wallet_placeholder": "Extra wallets - comma-separated (optional; shared watchlist is always included)",
    },
    {
        "label": "🕵️ Victim Collator",
        "filename": "victim_collator.py",
        "description": "Counts unique potential victims of one flagged wallet (ETH/BTC/XRP)",
        "wallet_input": "single",
        "wallet_placeholder": "Target wallet (leave blank for the script's built-in example)",
    },
    {
        "label": "📡 Crypto Address Watcher",
        "filename": "crypto_address_watcher.py",
        "description": "Scans blogs/Telegram/X for new crypto addresses, saves to Excel",
        "wallet_input": None,
        "wallet_placeholder": None,
    },
    {
        "label": "🧭 Link Tracer",
        "filename": "link_tracer.py",
        "description": "Traces funds hop-by-hop between a wallet and a flagged illicit wallet. Use the toggle to switch which direction it follows.",
        "wallet_input": "single",
        "wallet_placeholder": "Victim wallet to trace FROM (leave blank for the script's built-in example)",
        "supports_direction": True,
        "supports_amount_filter": True,
        "amount_placeholder": "Starting amount to track (optional, e.g. 23080.283377) - cuts out unrelated dust/other-customer activity",
    },
]

# --------------------------------------------------------------
# The folder this dashboard lives in - all scripts are expected to
# be found here. This is worked out automatically, no need to edit.
# --------------------------------------------------------------
SCRIPT_FOLDER = os.path.dirname(os.path.abspath(__file__))

# Same file crypto_address_watcher.py writes to and wallet_watcher.py
# reads from - lets the dashboard show what's been auto-discovered.
CASE_WATCHLIST_FILE = os.path.join(SCRIPT_FOLDER, "case_watchlist.json")


# ====================================================================
# SECTION 2: THE DASHBOARD APPLICATION
# (you shouldn't need to edit anything below this line)
# ====================================================================

class ThreatIntelDashboard:
    """
    PLAIN ENGLISH: This class builds and controls the entire dashboard
    window - the buttons, the output panel, and the logic that runs
    each script and displays its results live.
    """

    def __init__(self, root_window):
        self.root = root_window
        self.root.title("Threat Intel Dashboard")
        self.root.geometry("1150x650")
        self.root.configure(bg="#1e1e2e")

        # Keeps track of whether a script is currently running, so we
        # can stop the user from launching two scripts at once (which
        # would jumble their output together).
        self.is_running = False
        self.current_process = None

        # Which report style to run scripts in: "technical" (full detail,
        # raw addresses/tx hashes) or "simple" (plain-language, jury/
        # solicitor-friendly, with consistent short wallet labels).
        # Passed to every script via the OUTPUT_STYLE environment
        # variable when it's launched.
        self.output_style = tk.StringVar(value="technical")

        # Remembers the last script run, so toggling the style above can
        # automatically re-run it in the new style without the user
        # having to re-enter wallets and click the button again.
        self.last_script_info = None

        # A thread-safe queue is how the background thread (running
        # the script) safely hands text back to the main window thread
        # (which is the only thread allowed to update the display).
        self.output_queue = queue.Queue()

        self._build_header()
        self._build_style_toggle()
        self._build_button_panel()
        self._build_output_panel()
        self._build_status_bar()

        # This starts a repeating check (every 100 milliseconds) for
        # any new output waiting in the queue, so the display updates
        # smoothly while a script runs in the background.
        self.root.after(100, self._poll_output_queue)

    # ----------------------------------------------------------------
    # UI BUILDING METHODS
    # ----------------------------------------------------------------

    def _build_header(self):
        """PLAIN ENGLISH: Builds the title bar at the top of the window."""
        header = tk.Frame(self.root, bg="#1e1e2e")
        header.pack(fill="x", padx=20, pady=(15, 5))

        title = tk.Label(
            header, text="🛡️  Threat Intel Dashboard",
            font=("Segoe UI", 18, "bold"), fg="#cdd6f4", bg="#1e1e2e",
        )
        title.pack(anchor="w")

        subtitle = tk.Label(
            header, text="Click a button below to run a script. Results appear underneath.",
            font=("Segoe UI", 10), fg="#a6adc8", bg="#1e1e2e",
        )
        subtitle.pack(anchor="w")

    def _build_style_toggle(self):
        """
        PLAIN ENGLISH: Builds the Technical / Simple view toggle shown
        just under the title. This controls how every script's RESULTS
        are worded - Technical shows full detail (raw addresses, tx
        hashes); Simple shows plain language with short, consistent
        wallet labels ("Wallet A", "Wallet B", a legend at the end) -
        the version you'd show a solicitor, victim, or in court.

        Switching this AFTER a script has already run automatically
        re-runs that same script in the new style, so you don't have
        to re-enter anything.
        """
        toggle_frame = tk.Frame(self.root, bg="#1e1e2e")
        toggle_frame.pack(fill="x", padx=20, pady=(2, 8))

        tk.Label(
            toggle_frame, text="Report style:", font=("Segoe UI", 10),
            fg="#a6adc8", bg="#1e1e2e",
        ).pack(side="left", padx=(0, 10))

        self.style_buttons = {}
        for value, label in (("technical", "🎓 Technical"), ("simple", "👤 Simple (Jury-Friendly)")):
            button = tk.Button(
                toggle_frame, text=label, font=("Segoe UI", 9, "bold"),
                relief="flat", padx=12, pady=4, cursor="hand2",
                command=lambda value=value: self._set_output_style(value),
            )
            button.pack(side="left", padx=4)
            self.style_buttons[value] = button

        self._refresh_style_button_colors()

    def _refresh_style_button_colors(self):
        """Highlights whichever style button is currently active."""
        for value, button in self.style_buttons.items():
            if value == self.output_style.get():
                button.config(bg="#89b4fa", fg="#1e1e2e", activebackground="#74a8f9")
            else:
                button.config(bg="#45475a", fg="#cdd6f4", activebackground="#585b70")

    def _set_output_style(self, value):
        if self.output_style.get() == value:
            return
        self.output_style.set(value)
        self._refresh_style_button_colors()

        if self.is_running:
            # Can't safely interrupt a script that's already running -
            # the new style will just apply to whatever's run next.
            self.status_var.set(f"Report style set to {value.upper()} - applies to the next run.")
            return

        if self.last_script_info is not None:
            self.status_var.set(f"Re-running {self.last_script_info['label']} in {value.upper()} style...")
            self._run_script_button_clicked(self.last_script_info)
        else:
            self.status_var.set(f"Report style set to {value.upper()}.")

    def _build_button_panel(self):
        """
        PLAIN ENGLISH: Builds one button per script, using the SCRIPTS
        list defined in Section 1. Each button, when clicked, will
        launch that script.
        """
        button_frame = tk.Frame(self.root, bg="#1e1e2e")
        button_frame.pack(fill="x", padx=20, pady=10)

        self.buttons = []

        # Maps a script's filename -> its wallet Entry widget, so we
        # can read whatever the user typed when that script's button
        # is clicked. Only populated for scripts that take a wallet.
        self.wallet_entries = {}

        # Maps a script's filename -> its current direction ("forward"
        # or "backward") and the toggle Button widget itself. Only
        # populated for scripts with "supports_direction": True (just
        # Link Tracer, for now).
        self.direction_vars = {}
        self.direction_buttons = {}

        # Maps a script's filename -> its starting-amount Entry widget.
        # Only populated for scripts with "supports_amount_filter": True.
        self.amount_entries = {}

        # LOOP: create one button + description label (+ address box,
        # if this script accepts one) for every script entry defined
        # in the SCRIPTS list above.
        for script_info in SCRIPTS:
            card = tk.Frame(button_frame, bg="#313244", padx=12, pady=10)
            card.pack(side="left", expand=True, fill="both", padx=8)

            # The lambda here captures the CURRENT script_info for this
            # specific button, so each button runs its own correct
            # script rather than always running the last one in the list.
            button = tk.Button(
                card, text=script_info["label"],
                font=("Segoe UI", 11, "bold"),
                bg="#89b4fa", fg="#1e1e2e", activebackground="#74a8f9",
                relief="flat", padx=10, pady=8, cursor="hand2",
                command=lambda info=script_info: self._run_script_button_clicked(info),
            )
            button.pack(fill="x")
            self.buttons.append(button)

            description = tk.Label(
                card, text=script_info["description"], wraplength=220,
                font=("Segoe UI", 9), fg="#bac2de", bg="#313244", justify="left",
            )
            description.pack(pady=(8, 0), anchor="w")

            # Only scripts with a "wallet_input" type get an address
            # box - the Crypto Address Watcher doesn't take a wallet.
            if script_info.get("wallet_input"):
                self._add_wallet_entry(card, script_info)

            # Scripts that can trace either direction (currently just
            # Link Tracer) get a toggle button to switch between them.
            if script_info.get("supports_direction"):
                self._add_direction_toggle(card, script_info)

            # Scripts that support amount-based filtering (currently
            # just Link Tracer) get an extra small box for the amount.
            if script_info.get("supports_amount_filter"):
                self._add_amount_entry(card, script_info)

        # A separate "Open Reports Folder" button, since it doesn't
        # belong to any one script - it just opens the folder where
        # any Excel reports get saved.
        open_folder_button = tk.Button(
            button_frame, text="📂 Open Reports Folder",
            font=("Segoe UI", 10), bg="#585b70", fg="#cdd6f4",
            relief="flat", padx=10, pady=8, cursor="hand2",
            command=self._open_reports_folder,
        )
        open_folder_button.pack(side="left", padx=8)

        # Shows what crypto_address_watcher.py has automatically added
        # to the shared watchlist that wallet_watcher.py reads from.
        view_watchlist_button = tk.Button(
            button_frame, text="🔗 View Shared Watchlist",
            font=("Segoe UI", 10), bg="#585b70", fg="#cdd6f4",
            relief="flat", padx=10, pady=8, cursor="hand2",
            command=self._view_shared_watchlist,
        )
        view_watchlist_button.pack(side="left", padx=8)

        # Opens the most recently generated visual diagram (from
        # link_tracer.py or victim_collator.py running in Simple View)
        # in the default web browser.
        open_diagram_button = tk.Button(
            button_frame, text="📊 Open Visual Diagram",
            font=("Segoe UI", 10), bg="#585b70", fg="#cdd6f4",
            relief="flat", padx=10, pady=8, cursor="hand2",
            command=self._open_latest_visual_diagram,
        )
        open_diagram_button.pack(side="left", padx=8)

    def _add_wallet_entry(self, card, script_info):
        """
        PLAIN ENGLISH: Adds a small text box to a script's card where
        the user can type in one or more wallet addresses to check,
        instead of having to open the script file and edit the
        address list in the code. Shows light grey placeholder text
        that clears itself the moment the user starts typing.
        """
        placeholder = script_info["wallet_placeholder"]

        entry = tk.Entry(
            card, font=("Consolas", 9),
            bg="#1e1e2e", fg="#7f849c", insertbackground="#cdd6f4",
            relief="flat",
        )
        entry.pack(fill="x", pady=(8, 0), ipady=4)
        entry.insert(0, placeholder)

        def on_focus_in(event, entry=entry, placeholder=placeholder):
            if entry.get() == placeholder:
                entry.delete(0, "end")
                entry.config(fg="#cdd6f4")

        def on_focus_out(event, entry=entry, placeholder=placeholder):
            if not entry.get().strip():
                entry.insert(0, placeholder)
                entry.config(fg="#7f849c")

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)

        # Stash the placeholder text on the widget itself so we can
        # reliably tell "empty" apart from "user typed something" when
        # we come to read it back in _get_wallet_args.
        entry.placeholder_text = placeholder
        self.wallet_entries[script_info["filename"]] = entry

    def _add_direction_toggle(self, card, script_info):
        """
        PLAIN ENGLISH: Adds a single button that flips between FORWARD
        (start at a victim wallet, follow money out looking for a
        flagged illicit wallet) and BACKWARD (start at an illicit
        wallet, follow money in looking for where it came from - e.g.
        a KYC'd exchange). Clicking it just flips the mode and updates
        its own label/color plus the address box's placeholder text -
        no separate dropdown or checkbox needed.
        """
        filename = script_info["filename"]
        self.direction_vars[filename] = "forward"

        toggle_button = tk.Button(
            card, text="➡️  Direction: FORWARD  (victim ➜ illicit wallet)",
            font=("Segoe UI", 9, "bold"),
            bg="#a6e3a1", fg="#1e1e2e", activebackground="#94d3a2",
            relief="flat", padx=8, pady=6, cursor="hand2",
            command=lambda: self._toggle_direction(script_info),
        )
        toggle_button.pack(fill="x", pady=(8, 0))
        self.direction_buttons[filename] = toggle_button

    def _toggle_direction(self, script_info):
        """
        PLAIN ENGLISH: Runs when the direction toggle button is
        clicked. Flips forward<->backward, recolors/relabels the
        button so the current mode is obvious at a glance, and - if
        the address box is still showing placeholder text (the user
        hasn't typed their own wallet yet) - swaps the placeholder to
        match, so it's clear which kind of wallet to enter.
        """
        filename = script_info["filename"]
        current_direction = self.direction_vars.get(filename, "forward")
        new_direction = "backward" if current_direction == "forward" else "forward"
        self.direction_vars[filename] = new_direction

        button = self.direction_buttons[filename]
        entry = self.wallet_entries.get(filename)

        if new_direction == "forward":
            button.config(text="➡️  Direction: FORWARD  (victim ➜ illicit wallet)", bg="#a6e3a1")
            new_placeholder = "Victim wallet to trace FROM (leave blank for the script's built-in example)"
        else:
            button.config(text="⬅️  Direction: BACKWARD  (illicit wallet ➜ source)", bg="#f9e2af")
            new_placeholder = "Illicit wallet to trace BACKWARD from (leave blank for the script's built-in example)"

        if entry is not None:
            was_showing_placeholder = entry.get() == getattr(entry, "placeholder_text", None)
            entry.placeholder_text = new_placeholder
            if was_showing_placeholder:
                entry.config(fg="#7f849c")
                entry.delete(0, "end")
                entry.insert(0, new_placeholder)

    def _add_amount_entry(self, card, script_info):
        """
        PLAIN ENGLISH: Adds a small text box for an optional starting
        amount - if the user knows how much the victim actually sent
        (or how much moved through the illicit wallet), typing it here
        makes the trace ignore hops that clearly aren't part of that
        money, cutting down the number of unrelated addresses shown.
        Leave it blank/placeholder to trace every hop regardless of
        size, same as before this feature existed.
        """
        placeholder = script_info["amount_placeholder"]
        filename = script_info["filename"]

        entry = tk.Entry(
            card, font=("Consolas", 9),
            bg="#1e1e2e", fg="#7f849c", insertbackground="#cdd6f4",
            relief="flat",
        )
        entry.pack(fill="x", pady=(8, 0), ipady=4)
        entry.insert(0, placeholder)

        def on_focus_in(event, entry=entry, placeholder=placeholder):
            if entry.get() == placeholder:
                entry.delete(0, "end")
                entry.config(fg="#cdd6f4")

        def on_focus_out(event, entry=entry, placeholder=placeholder):
            if not entry.get().strip():
                entry.insert(0, placeholder)
                entry.config(fg="#7f849c")

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)

        entry.placeholder_text = placeholder
        self.amount_entries[filename] = entry

    def _get_amount_arg(self, script_info):
        """
        PLAIN ENGLISH: Reads whatever the user typed into the starting-
        amount box and returns it as a string to hand to the script,
        or "" if it's empty/still showing placeholder text (which
        means "don't filter by amount"). Doesn't validate that it's a
        real number here - link_tracer.py already does that itself
        and will explain clearly if something unparseable gets through.
        """
        entry = self.amount_entries.get(script_info["filename"])
        if entry is None:
            return ""
        typed_value = entry.get().strip()
        if not typed_value or typed_value == getattr(entry, "placeholder_text", None):
            return ""
        return typed_value

    def _get_wallet_args(self, script_info):
        """
        PLAIN ENGLISH: Reads whatever the user typed into a script's
        address box (if it has one) and turns it into the command-line
        arguments to pass to that script. Returns an empty list if the
        box is empty/still showing placeholder text, which tells the
        script to fall back to its own built-in example wallet(s).
        """
        entry = self.wallet_entries.get(script_info["filename"])
        if entry is None:
            return []

        typed_value = entry.get().strip()
        if not typed_value or typed_value == getattr(entry, "placeholder_text", None):
            return []

        # Both "multi" and "single" scripts accept one comma-separated
        # string as a single argument - wallet_watcher.py and
        # victim_collator.py both know how to parse this.
        return [typed_value]

    def _build_output_panel(self):
        """
        PLAIN ENGLISH: Builds the large scrolling text area where the
        live results of whichever script is running get displayed.
        """
        output_frame = tk.Frame(self.root, bg="#1e1e2e")
        output_frame.pack(fill="both", expand=True, padx=20, pady=10)

        label = tk.Label(
            output_frame, text="Results:",
            font=("Segoe UI", 10, "bold"), fg="#cdd6f4", bg="#1e1e2e",
        )
        label.pack(anchor="w")

        self.output_box = scrolledtext.ScrolledText(
            output_frame, wrap="word", font=("Consolas", 10),
            bg="#11111b", fg="#cdd6f4", insertbackground="#cdd6f4",
            relief="flat", padx=10, pady=10,
        )
        self.output_box.pack(fill="both", expand=True)

        # These are "tags" - styling rules we can apply to specific
        # lines of text later. We use them to make ALERT lines stand
        # out in bright red/bold, and error lines in orange.
        self.output_box.tag_config("alert", foreground="#f38ba8", font=("Consolas", 10, "bold"))
        self.output_box.tag_config("warning", foreground="#fab387")
        self.output_box.tag_config("success", foreground="#a6e3a1")
        self.output_box.tag_config("dim", foreground="#7f849c")

        self.output_box.config(state="disabled")  # Read-only for the user

    def _build_status_bar(self):
        """PLAIN ENGLISH: Builds the thin status strip at the bottom of the window."""
        self.status_var = tk.StringVar(value="Ready. Click a button above to begin.")
        status_bar = tk.Label(
            self.root, textvariable=self.status_var, anchor="w",
            font=("Segoe UI", 9), fg="#a6adc8", bg="#181825", padx=10, pady=6,
        )
        status_bar.pack(fill="x", side="bottom")

    # ----------------------------------------------------------------
    # SCRIPT EXECUTION LOGIC
    # ----------------------------------------------------------------

    def _run_script_button_clicked(self, script_info):
        """
        PLAIN ENGLISH: This runs when the user clicks one of the script
        buttons. It checks the script file actually exists, then hands
        off the real work to a background thread so the window doesn't
        freeze while the script runs.
        """
        # CONDITIONAL: don't allow starting a second script while one
        # is already running - their output would get jumbled together.
        if self.is_running:
            messagebox.showwarning(
                "Script already running",
                "Please wait for the current script to finish before starting another.",
            )
            return

        script_path = os.path.join(SCRIPT_FOLDER, script_info["filename"])

        # CONDITIONAL: check the script file actually exists in this
        # folder before trying to run it, and give a clear message if not.
        if not os.path.isfile(script_path):
            messagebox.showerror(
                "Script not found",
                f"Could not find '{script_info['filename']}' in this folder:\n\n{SCRIPT_FOLDER}\n\n"
                "Make sure all script files are saved in the same folder as this dashboard.",
            )
            return

        wallet_args = self._get_wallet_args(script_info)

        # Scripts with a direction toggle (Link Tracer) need FOUR
        # positional args: wallet, target_wallets (left blank here -
        # the script falls back to its own settings/shared watchlist),
        # direction, and starting_amount (blank = no amount filter).
        # Other scripts are unaffected and keep getting just the
        # wallet arg as before.
        direction = None
        amount_arg = ""
        if script_info.get("supports_direction"):
            direction = self.direction_vars.get(script_info["filename"], "forward")
            amount_arg = self._get_amount_arg(script_info)
            wallet_value = wallet_args[0] if wallet_args else ""
            extra_args = [wallet_value, "", direction, amount_arg]
        else:
            extra_args = wallet_args

        self._clear_output()
        self._append_output(f"Starting {script_info['label']}...\n", "dim")
        if wallet_args:
            self._append_output(f"Using wallet(s) from the box above: {wallet_args[0]}\n", "dim")
        if direction:
            self._append_output(f"Direction: {direction.upper()}\n", "dim")
        if amount_arg:
            self._append_output(f"Amount filter: tracking ~{amount_arg}\n", "dim")
        self.status_var.set(f"Running {script_info['label']}...")
        self._set_buttons_enabled(False)
        self.is_running = True
        self.last_script_info = script_info

        # A "thread" lets the script run in the background while the
        # window itself stays responsive (so it doesn't look frozen).
        # daemon=True means this thread will not prevent the app from
        # closing if the user closes the window mid-run.
        worker_thread = threading.Thread(
            target=self._execute_script,
            args=(script_path, extra_args, self.output_style.get()),
            daemon=True,
        )
        worker_thread.start()

    def _execute_script(self, script_path, extra_args=None, output_style="technical"):
        """
        PLAIN ENGLISH: This runs on the BACKGROUND thread. It actually
        launches the chosen script as a separate program (using the
        same Python that's running this dashboard) and reads its
        output line by line as it happens, passing each line back to
        the main window via the queue.
        """
        try:
            # PLAIN ENGLISH: Python normally holds onto printed text in
            # a memory buffer and only sends it out in batches - fine
            # for a terminal, but it means a script running inside
            # another program can appear to produce NO output for a
            # long time, then dump everything at once. The "-u" flag
            # tells the script's Python interpreter to send every line
            # out immediately instead of batching it. We also set the
            # PYTHONUNBUFFERED environment variable as a second,
            # belt-and-suspenders way of forcing the same behavior.
            #
            # We ALSO force UTF-8 text encoding via PYTHONIOENCODING.
            # Without this, on Windows, a script that prints emoji (like
            # our 🚨 alert banners) can crash with a "charmap codec"
            # error, because Windows' older default text encoding
            # (cp1252) has no way to represent emoji characters at all.
            unbuffered_env = os.environ.copy()
            unbuffered_env["PYTHONUNBUFFERED"] = "1"
            unbuffered_env["PYTHONIOENCODING"] = "utf-8"
            unbuffered_env["OUTPUT_STYLE"] = output_style

            # sys.executable is the exact Python program currently
            # running this dashboard - using it guarantees we launch
            # the script with a working Python installation, matching
            # whatever the user already has set up.
            command = [sys.executable, "-u", script_path] + (extra_args or [])

            self.current_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=SCRIPT_FOLDER,
                env=unbuffered_env,
            )

            # LOOP: read the script's output one line at a time, as
            # soon as each line becomes available, and place it in the
            # queue for the main window to display. We also count how
            # many lines we actually received, so we can warn the user
            # afterwards if the script produced nothing at all.
            lines_received = 0
            for line in self.current_process.stdout:
                self.output_queue.put(line)
                lines_received += 1

            self.current_process.wait()
            exit_code = self.current_process.returncode

            # CONDITIONAL: if the script ran but never printed a single
            # line, that's almost always a setup problem (e.g. a
            # missing API key causing an instant, silent exit before
            # our usual warning message got flushed) - tell the user
            # plainly instead of leaving a blank panel with no clues.
            if lines_received == 0:
                self.output_queue.put(
                    "[NOTE] The script produced no output at all. This usually means it "
                    "exited immediately - for example, a missing API key, a missing "
                    "settings value, or the wrong Python being used. Double-check the "
                    "settings near the top of that script file.\n"
                )

            # CONDITIONAL: report whether the script finished cleanly
            # (exit code 0) or hit a problem (any other exit code).
            if exit_code == 0:
                self.output_queue.put("\n[DONE] Script finished successfully.\n")
            else:
                self.output_queue.put(f"\n[DONE] Script exited with a problem (code {exit_code}).\n")

        except Exception as error:
            self.output_queue.put(f"\n[ERROR] Could not run script: {error}\n")

        finally:
            # Signal to the main thread that we're finished, so it can
            # re-enable the buttons.
            self.output_queue.put("__SCRIPT_FINISHED__")

    def _poll_output_queue(self):
        """
        PLAIN ENGLISH: This runs automatically every 100 milliseconds
        on the main window thread. It checks whether the background
        script has sent any new lines of text, and if so, displays
        them in the results panel with the right coloring.
        """
        try:
            # LOOP: drain every line currently waiting in the queue
            # (there may be several ready at once) and display them.
            while True:
                line = self.output_queue.get_nowait()

                # CONDITIONAL: this special marker means the script has
                # fully finished, so re-enable the buttons for next use.
                if line == "__SCRIPT_FINISHED__":
                    self.is_running = False
                    self._set_buttons_enabled(True)
                    self.status_var.set("Ready. Click a button above to begin.")
                    continue

                self._append_output_with_smart_coloring(line)

        except queue.Empty:
            # This is expected and normal - it just means there's no
            # new output right now. We just try again in 100ms.
            pass

        # Reschedule this same check to run again shortly.
        self.root.after(100, self._poll_output_queue)

    def _append_output_with_smart_coloring(self, line):
        """
        PLAIN ENGLISH: Looks at a line of script output and decides how
        to color it - bright red for alerts, orange for warnings, green
        for success checkmarks, or plain white for everything else.
        """
        if "🚨" in line or "ALERT" in line:
            self._append_output(line, "alert")
        elif "⚠️" in line or "[ERROR]" in line:
            self._append_output(line, "warning")
        elif "✅" in line or "📊" in line:
            self._append_output(line, "success")
        else:
            self._append_output(line, None)

    def _append_output(self, text, tag):
        """PLAIN ENGLISH: Safely adds a line of text to the results panel."""
        self.output_box.config(state="normal")
        if tag:
            self.output_box.insert("end", text, tag)
        else:
            self.output_box.insert("end", text)
        self.output_box.see("end")  # Auto-scroll to the latest line
        self.output_box.config(state="disabled")

    def _clear_output(self):
        """PLAIN ENGLISH: Wipes the results panel clean before a new run."""
        self.output_box.config(state="normal")
        self.output_box.delete("1.0", "end")
        self.output_box.config(state="disabled")

    def _set_buttons_enabled(self, enabled):
        """
        PLAIN ENGLISH: Turns all the script buttons (and any direction
        toggles / amount boxes) on or off. We turn them off while a
        script is running so the user can't accidentally start two at
        once, or change settings mid-run.
        """
        new_state = "normal" if enabled else "disabled"
        for button in self.buttons:
            button.config(state=new_state)
        for button in self.direction_buttons.values():
            button.config(state=new_state)
        for entry in self.amount_entries.values():
            entry.config(state=new_state)

    def _view_shared_watchlist(self):
        """
        PLAIN ENGLISH: Reads the shared case_watchlist.json file (the
        one crypto_address_watcher.py appends new discoveries to, and
        wallet_watcher.py automatically checks) and prints its
        contents into the results panel, so you can see at a glance
        what's being cross-fed between the two tools without opening
        the JSON file by hand.
        """
        if self.is_running:
            messagebox.showwarning(
                "Script already running",
                "Please wait for the current script to finish first.",
            )
            return

        self._clear_output()

        if not os.path.isfile(CASE_WATCHLIST_FILE):
            self._append_output(
                "No shared case watchlist yet.\n\n"
                "This file is created automatically the first time "
                "Crypto Address Watcher finds a new address. Run it "
                "once, then check back here.\n",
                "dim",
            )
            return

        try:
            with open(CASE_WATCHLIST_FILE, "r", encoding="utf-8") as file_handle:
                entries = json.load(file_handle)
        except (json.JSONDecodeError, OSError) as error:
            self._append_output(f"[ERROR] Could not read the shared watchlist: {error}\n", "warning")
            return

        if not entries:
            self._append_output("Shared case watchlist is empty (no new addresses found yet).\n", "dim")
            return

        self._append_output(
            f"SHARED CASE WATCHLIST — {len(entries)} address(es)\n"
            f"(auto-discovered by Crypto Address Watcher, auto-checked by Wallet Watcher)\n\n",
            "success",
        )
        for entry in entries:
            self._append_output(f"  {entry.get('address', '?')}  [{entry.get('chain', '?')}]\n", None)
            self._append_output(
                f"    First seen : {entry.get('first_seen_utc', '?')}\n"
                f"    Source     : {entry.get('source', '?')}\n"
                f"    Context    : {entry.get('context', '')}\n\n",
                "dim",
            )

    def _open_latest_visual_diagram(self):
        """
        PLAIN ENGLISH: Finds the most recently generated visual
        diagram (an HTML file saved by link_tracer.py or
        victim_collator.py when run in Simple/Jury-Friendly View) and
        opens it in the default web browser. These live in the same
        "trace_reports" folder as the CSV/plain-text exports.
        """
        search_folder = os.path.join(SCRIPT_FOLDER, "trace_reports")
        diagram_files = glob.glob(os.path.join(search_folder, "*.html"))

        if not diagram_files:
            messagebox.showinfo(
                "No visual diagram yet",
                "No visual diagram has been generated yet.\n\n"
                "Run Link Tracer or Victim Collator with the report style set to "
                "👤 Simple (Jury-Friendly) - a diagram is saved automatically "
                "alongside the usual text report.",
            )
            return

        newest_file = max(diagram_files, key=os.path.getmtime)
        webbrowser.open(f"file://{newest_file}")
        self.status_var.set(f"Opened diagram: {os.path.basename(newest_file)}")

    def _open_reports_folder(self):
        """
        PLAIN ENGLISH: Opens the folder containing this dashboard (and
        therefore any Excel reports the scripts have saved) in the
        computer's normal file browser, adapting to whichever
        operating system the user is on.
        """
        system_name = platform.system()
        try:
            if system_name == "Windows":
                os.startfile(SCRIPT_FOLDER)
            elif system_name == "Darwin":  # macOS
                subprocess.run(["open", SCRIPT_FOLDER])
            else:  # Linux and others
                subprocess.run(["xdg-open", SCRIPT_FOLDER])
        except Exception as error:
            messagebox.showerror("Could not open folder", str(error))


# ====================================================================
# SECTION 3: PROGRAM ENTRY POINT
# This is the part that actually runs when you type
# "python threat_intel_dashboard.py" in your terminal.
# ====================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatIntelDashboard(root)
    root.mainloop()
