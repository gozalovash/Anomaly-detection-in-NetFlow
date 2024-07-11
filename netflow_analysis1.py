import json
import pandas as pd
import statistics
import operator_country
from collections import Counter
import plotly.express as px

def load_dataset(data_file):
    with open(data_file) as file_logs:
        json_data = json.load(file_logs)
    return pd.DataFrame(json_data)

def prepare_dataset(df, start_time_column):
    df[start_time_column] = pd.to_datetime(df[start_time_column], utc=True)
    return

def operator_country_identification(df, start_time_column):
    df['possible_timezones'] = df[start_time_column].apply(operator_country.possible_timezone)
    df['country_codes'] = df['possible_timezones'].apply(lambda tz_list: [operator_country.timezone_to_country_code(tz) for tz in tz_list])
    all_country_codes = [code for sublist in df['country_codes'] for code in sublist if code is not None]
    country_code_counts = Counter(all_country_codes)
    # Convert to DataFrame for plotting
    country_df = pd.DataFrame(country_code_counts.items(), columns=['country', 'count'])
    country_df['country'] = country_df['country'].apply(operator_country.alpha2_to_alpha3)
    country_df = country_df.dropna()
    build_choropleth(country_df, 'country', 'count')
    return df

def build_choropleth(df, location, color):
    fig = px.choropleth(
        df,
        locations=location,
        color=color,
        hover_name="country",
        title="Choropleth Map of Timezone Occurrences by Country"
    )
    # Show the map
    fig.show()

def main():
    df = load_dataset('netflow_file_ext_fixed.json')
    df_filtered = df[df['selectorIp'] == "103.151.229.124"]
    prepare_dataset(df_filtered, 'startTime')
    updated_df = operator_country_identification(df_filtered, 'startTime')\

    print(f'10 Most likely timezones:', statistics.most_likely_timezone(updated_df, 'possible_timezones', 10))
    return

if __name__ == "__main__":
    main()