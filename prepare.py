import pandas as pd
import numpy as np

def fixing_col_names(df):
    """
    This function removes leading whitespace, '/s' characters and replaces spaces with '_'.
    """
    #Lists to capture alterations
    column_names = list(df.columns)
    fixed_names = []
    
    for item in column_names:
        #Removes leading whitespace
        if item[0].isspace():
            item = item[1:]
            item.replace(" ", "")
        #Removes '/s'
        if item[-2:] == "/s":
            item = item[:-2]
        #Removes '.1'
        if item[-2:] == ".1":
            item = item[:-2]
        #Replaces space with underscore
        item = item.replace(" ", "_")
        fixed_names.append(item)
    
    #Replaces names in the DataFrame
    df.rename(columns=dict(zip(column_names, fixed_names)), inplace=True)
    return df