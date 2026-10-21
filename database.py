import os
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Supabase client
supabase_url = os.getenv('SUPABASE_URL') or os.getenv('DATABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY', '')

supabase: Client = create_client(
    supabase_url=supabase_url,
    supabase_key=supabase_key
)

def get_db():
    return supabase