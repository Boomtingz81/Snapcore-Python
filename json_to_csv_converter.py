def load_dataset(json_file):
with open(json_file, 'r', encoding='utf-8') as f:
data = json.load(f)
return data

def save_csv(commands, filename):
# Determine headers dynamically based on keys in commands
headers = set()
for cmd in commands:
headers.update(cmd.keys())
headers = sorted(headers)
with open(filename, 'w', newline='', encoding='utf-8') as f:
writer = csv.DictWriter(f, fieldnames=headers)
writer.writeheader()
for cmd in commands:
writer.writerow(cmd)

def main():
# Load dataset
dataset = load_dataset('mic3x2x_obd_dataset.json')

# Extract commands
at_commands = dataset.get('AT_COMMANDS', [])
vt_commands = dataset.get('VT_COMMANDS', [])

# Save CSV files
save_csv(at_commands, 'at_commands.csv')
save_csv(vt_commands, 'vt_commands.csv')

print(f"Loaded {len(at_commands)} AT commands")
print(f"Loaded {len(vt_commands)} VT commands")

# Parse CLI arguments
parser = argparse.ArgumentParser(description='Filter commands by CAN extension')
parser.add_argument('--filter', type=str, default=None, help='Filter commands by string in can_ext (e.g., CAN)')
args = parser.parse_args()

if args.filter:
filter_str = args.filter.upper()
# Combine all commands for filtering
combined = at_commands + vt_commands
filtered_cmds = [cmd for cmd in combined if 'can_ext' in cmd and filter_str in str(cmd['can_ext']).upper()]
for cmd in filtered_cmds:
print(cmd)

if __name__ == '__main__':
main()
