import os
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Supabase client
supabase: Client = create_client(
    supabase_url=os.getenv('DATABASE_URL'),
    supabase_key=os.getenv('SUPABASE_KEY', '')
)

def get_db():
    return supabase