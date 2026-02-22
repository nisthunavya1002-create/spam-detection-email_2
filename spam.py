import os
import re
import csv
import imaplib
import email
import random
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from email.header import decode_header


# Default folder where .txt emails will be saved and read from
DEFAULT_FOLDER='/Users/rushil/Documents/Python_Stuff/Spam_detect/emails'

# Sets of keywords used to identify different email types
SPAM_WORDS={'lottery', 'winner', 'free', 'claim', 'urgent', 'money', 'prize', 'congratulations',
              'click here', 'act now', 'limited time', 'buy now', 'cash', 'win', 'subscribe'}
PROMO_WORDS={'discount', 'offer', 'sale', 'deal', 'save', 'coupon', 'special', 'promo', 'exclusive',
               'newsletter', 'shop', 'clearance', 'buy', 'order'}
IMPORTANT_WORDS={'project', 'meeting', 'deadline', 'invoice', 'schedule', 'payment', 'client',
                   'report', 'proposal', 'action required', 'follow up', 'important', 'urgent', 'appointment'}

# Thresholds for deciding which type dominates
SPAM_THRESHOLD=2
PROMO_THRESHOLD=2
IMPORTANT_THRESHOLD=2



def clean_text(text: str) -> str:
    #Convert text to lowercase, remove extra spaces, and trim.
    if not text:
        return ''
    text=text.lower()
    text=re.sub(r'\s+', ' ', text)  # replace multiple spaces/newlines with single space
    return text.strip()

def find_matches(text: str, keywords: set) -> list:
    #Return a list of keywords that appear in the given text. Using a set, to remove all duplicates.
    return [k for k in keywords if k in text]

def classify_email(text: str) -> dict:
    #Classify email text as Spam, Promotional, or Important.
    text_clean=clean_text(text)

    # Count keyword matches
    spam_matches=find_matches(text_clean, SPAM_WORDS)
    promo_matches=find_matches(text_clean, PROMO_WORDS)
    important_matches=find_matches(text_clean, IMPORTANT_WORDS)

    spam_score=len(spam_matches)
    promo_score=len(promo_matches)
    important_score=len(important_matches)

    # Extra spam indicators: ALL CAPS and exclamation marks
    if re.search(r'[A-Z]{2,}', text):
        spam_score += 0.5
    spam_score += text.count('!') * 0.2

    # Extra importance indicators
    if 'invoice' in text_clean or 'payment' in text_clean or 'client' in text_clean:
        important_score += 1

    # Choose which label fits best
    label='Important'  # default assumption
    if spam_score >= SPAM_THRESHOLD and spam_score > promo_score and spam_score > important_score:
        label='Spam'
    elif promo_score >= PROMO_THRESHOLD and promo_score > spam_score and promo_score > important_score:
        label='Promotional'
    else:
        # If message is short and contains a link, likely a promo
        if len(text_clean) < 50 and ('http' in text_clean or 'www.' in text_clean):
            label='Promotional'
        else:
            label='Important'

    # Return details for logging/display
    return {
        'label': label,
        'spam_matches': spam_matches,
        'promo_matches': promo_matches,
        'important_matches': important_matches,
        'scores': {
            'spam_score': spam_score,
            'promo_score': promo_score,
            'important_score': important_score
        }
    }



def get_gmail_credentials():
    #Create a popup window to collect Gmail login info (no password masking).
    login_win=tk.Toplevel()
    login_win.title("Enter Gmail Credentials")
    login_win.geometry("350x180")
    login_win.resizable(False, False)

    # Email label + entry
    tk.Label(login_win, text="Gmail Address:", font=('Arial', 11)).pack(pady=(15, 5))
    email_entry=tk.Entry(login_win, width=40, font=('Arial', 11))
    email_entry.pack(pady=2)

    # Password label + entry (NOT masked)
    tk.Label(login_win, text="App Password:", font=('Arial', 11)).pack(pady=(10, 5))
    pass_entry=tk.Entry(login_win, width=40, font=('Arial', 11))
    pass_entry.pack(pady=2)

    result={"email": None, "password": None}

    # When "Submit" is clicked
    def submit():
        email_val=email_entry.get().strip()
        pass_val=pass_entry.get().strip()
        if not email_val or not pass_val:
            messagebox.showwarning("Missing info", "Please fill in both fields.")
            return
        result["email"]=email_val
        result["password"]=pass_val
        login_win.destroy()

    tk.Button(login_win, text="Submit", command=submit, font=('Arial', 11, 'bold')).pack(pady=12)
    login_win.grab_set()
    login_win.wait_window()
    return result["email"], result["password"]



def fetch_emails_from_gmail(save_folder: str, user: str, app_password: str, max_emails: int=10):
    #Connect to Gmail via IMAP, fetch recent emails, and save them as .txt files.
    imap_server="imap.gmail.com"
    saved_files=[]
    mail=None

    try:
        # Connect securely and log in
        mail=imaplib.IMAP4_SSL(imap_server)
        mail.login(user, app_password)
        mail.select("inbox")

        # Search all emails in the inbox
        status, data=mail.search(None, "ALL")
        if status !="OK":
            print("No messages found or search failed.")
            return saved_files

        email_ids=data[0].split()
        print(f"Total emails found: {len(email_ids)}")

        # Fetch the most recent 'max_emails'
        for i, eid in enumerate(reversed(email_ids[-max_emails:]), 1): 
            res, msg_data=mail.fetch(eid, "(RFC822)")
            if res != "OK":
                print(f"Error fetching email {eid}")
                continue

            msg=email.message_from_bytes(msg_data[0][1])

            # Extract From + Subject headers
            from_=msg.get("From", "Unknown sender")
            subject, enc=decode_header(msg.get("Subject", "No Subject"))[0]
            if isinstance(subject, bytes):
                subject=subject.decode(enc or "utf-8", errors="ignore")

            # Extract the email body (preferring text/plain parts)
            body=""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type=part.get_content_type()
                    content_disposition=str(part.get("Content-Disposition"))
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        body=part.get_payload(decode=True).decode("utf-8", errors="ignore")
                        break
            else:
                body=msg.get_payload(decode=True).decode("utf-8", errors="ignore")

            # Clean subject for use as filename
            safe_subject=re.sub(r'[^A-Za-z0-9_]+', '_', subject)[:50]
            filename=f"email_{i}_{safe_subject}.txt"
            file_path=os.path.join(save_folder, filename)

            # Save sender + body to a text file
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(f"From: {from_}\n\n{body.strip()}")

            saved_files.append(file_path)
            print(f"Saved: {file_path}")

    except imaplib.IMAP4.error as e:
        print("IMAP error:", e)
        messagebox.showerror("IMAP Error", str(e))
    finally:
        # Always close IMAP connection
        try:
            if mail is not None:
                mail.close()
                mail.logout()
        except Exception:
            pass

    return saved_files


class emailClassApp:
   #Main GUI application for classifying and fetching emails.

    def __init__(self, root):
        self.root=root
        self.root.title('Email Classifier (Gmail + Local Files)')
        self.root.geometry('850x650')

        # Variables for app state
        self.folder=DEFAULT_FOLDER
        self.file_list=[]
        self.index=0
        self.results=[]


        top_frame=tk.Frame(root)
        top_frame.pack(fill=tk.X, padx=10, pady=8)

        self.folder_label=tk.Label(top_frame, text=f'Folder: {self.folder}')
        self.folder_label.pack(side=tk.LEFT)

        tk.Button(top_frame, text='Load Folder', command=self.choose_folder).pack(side=tk.LEFT, padx=6)
        tk.Button(top_frame, text='Load .txt files', command=self.load_files).pack(side=tk.LEFT)
        tk.Button(top_frame, text='Fetch from Gmail', command=self.fetch_from_gmail).pack(side=tk.LEFT, padx=6)
        tk.Button(top_frame, text='Save results to CSV', command=self.save_results).pack(side=tk.RIGHT)

        mid_frame=tk.Frame(root)
        mid_frame.pack(fill=tk.BOTH, expand=True, padx=10)
        self.title_label=tk.Label(mid_frame, text='No file loaded', font=('Arial', 14, 'bold'))
        self.title_label.pack(anchor='w')
        self.text_area=tk.Text(mid_frame, wrap=tk.WORD, height=18, font=('Arial', 12))
        self.text_area.pack(fill=tk.BOTH, expand=True, pady=6)
        self.text_area.config(state=tk.DISABLED)

        self.bottom_frame=tk.Frame(root)
        self.bottom_frame.pack(fill=tk.X, padx=10, pady=8)
        self.result_label=tk.Label(self.bottom_frame, text='Result: N/A', font=('Arial', 12))
        self.result_label.pack(anchor='w')
        self.matches_label=tk.Label(self.bottom_frame, text='Matches: N/A')
        self.matches_label.pack(anchor='w')

        nav_frame=tk.Frame(self.bottom_frame)
        nav_frame.pack(fill=tk.X, pady=6)
        tk.Button(nav_frame, text='Previous', command=self.pre_file).pack(side=tk.LEFT)
        tk.Button(nav_frame, text='Classify', command=self.classify_current).pack(side=tk.LEFT, padx=8)
        tk.Button(nav_frame, text='Next', command=self.next_file).pack(side=tk.LEFT)
        tk.Button(nav_frame, text='Shuffle', command=self.shuffle_files).pack(side=tk.RIGHT)

        self.status_label=tk.Label(root, text='Status: Ready', anchor='w')
        self.status_label.pack(fill=tk.X, padx=10, pady=(0, 8))


        self.load_files()

    def choose_folder(self):
        """Let user pick a new folder and load .txt files from it."""
        folder_selected=filedialog.askdirectory()
        if folder_selected:
            self.folder=folder_selected
            self.folder_label.config(text=f'Folder: {self.folder}')
            self.load_files()

    def load_files(self):
        #Load all .txt files from the current folder.
        self.file_list=[]
        if not os.path.isdir(self.folder):
            self.status_label.config(text=f'Status: Folder not found: {self.folder}')
            return
        for f in sorted(os.listdir(self.folder)):
            if f.lower().endswith('.txt'):
                full=os.path.join(self.folder, f)
                try:
                    with open(full, 'r', encoding='utf-8') as fh:
                        content=fh.read().strip()
                        if content:
                            self.file_list.append(f)
                except Exception as e:
                    print(f'Error reading: {full, e}')
        if not self.file_list:
            self.status_label.config(text='Status: No .txt files found')
            self.title_label.config(text='No file loaded')
            self.text_area.config(state=tk.NORMAL)
            self.text_area.delete('1.0', tk.END)
            self.text_area.config(state=tk.DISABLED)
            return
        self.index=0
        self.results=[]
        self.status_label.config(text=f'Status: Loaded {len(self.file_list)} files')
        self.show_files()

    def fetch_from_gmail(self):
        #Ask for Gmail credentials and fetch recent emails.
        email_user, email_pass=get_gmail_credentials()
        if not email_user or not email_pass:
            messagebox.showinfo("Cancelled", "Gmail fetch cancelled.")
            return
        messagebox.showinfo("Fetching", "Connecting to Gmail. Please wait...")
        saved=fetch_emails_from_gmail(
            save_folder=self.folder,
            user=email_user,
            app_password=email_pass,
            max_emails=10
        )
        messagebox.showinfo("Done", f"Fetched and saved {len(saved)} emails.")
        self.load_files()


    def show_files(self):
        #Show current email file in text box.
        if not self.file_list:
            return
        fname=self.file_list[self.index]
        full=os.path.join(self.folder, fname)
        with open(full, 'r', encoding='utf-8') as fh:
            content=fh.read()
        self.title_label.config(text=f'[{self.index+1}/{len(self.file_list)}] {fname}')
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete('1.0', tk.END)
        self.text_area.insert(tk.END, content)
        self.text_area.config(state=tk.DISABLED)
        self.result_label.config(text='Result: N/A')
        self.matches_label.config(text='Matches - 0')
        self.status_label.config(text=f'Status: Ready - Viewing {fname}')

    def next_file(self):
        #Go to next file in the list.
        if self.index < len(self.file_list) - 1:
            self.index += 1
            self.show_files()
        else:
            messagebox.showinfo('End', 'No more files.')

    def pre_file(self):
        #Go to previous file in the list.
        if self.index > 0:
            self.index -= 1
            self.show_files()
        else:
            messagebox.showinfo('Start', 'This is the first file.')

    def shuffle_files(self):
        if not self.file_list:
            return
        random.shuffle(self.file_list)
        self.index=0
        self.show_files()

    def classify_current(self):
        if not self.file_list:
            messagebox.showwarning('No files detected', 'No email files loaded to classify')
            return
        fname=self.file_list[self.index]
        full=os.path.join(self.folder, fname)
        with open(full, 'r', encoding='utf-8') as fh:
            content=fh.read()
        res=classify_email(content)
        label=res['label']
        spam_m=res['spam_matches']
        promo_m=res['promo_matches']
        important_m=res['important_matches']
        scores=res['scores']
        self.result_label.config(
            text=f"Result: {label} (spam:{scores['spam_score']}, promo:{scores['promo_score']}, important:{scores['important_score']})")
        matches_text=f"spam: {', '.join(spam_m) if spam_m else '-'} | promo: {', '.join(promo_m) if promo_m else '-'} | important: {', '.join(important_m) if important_m else '-'}"
        self.matches_label.config(text=f'Matches: {matches_text}')

        # Save classification result internally
        detail={
            'filename': fname,
            'label': label,
            'spam_matches': ';'.join(spam_m),
            'promo_matches': ';'.join(promo_m),
            'important_matches': ';'.join(important_m),
            'spam_score': scores['spam_score'],
            'promo_score': scores['promo_score'],
            'important_score': scores['important_score']
        }

        replaced=False
        for i, r in enumerate(self.results):
            if r['filename'] == fname:
                self.results[i]=detail
                replaced=True
                break
        if not replaced:
            self.results.append(detail)

        self.status_label.config(text=f'Status: Classified {fname} as {label}')

    def save_results(self):
        if not self.results:
            messagebox.showwarning('No results', 'Please classify some emails first.')
            return
        save_path=filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files', '*.csv')])
        if not save_path:
            return
        fieldnames=['filename', 'label', 'spam_matches', 'promo_matches',
                      'important_matches', 'spam_score', 'promo_score', 'important_score']
        try:
            with open(save_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer=csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in self.results:
                    writer.writerow(row)
            messagebox.showinfo('Saved', f'Results saved to {save_path}')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to save CSV: {e}')


if __name__ == '__main__':
    root=tk.Tk()
    app=emailClassApp(root)
    root.mainloop()