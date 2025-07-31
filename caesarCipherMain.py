from src.caesarCipher import caesarCipher
import matplotlib.ticker as mticker
from collections import Counter
import matplotlib.pyplot as plt
from src.utils import checkPath
import pandas as pd
import argparse
import re
import os


def getConsoleArguments() -> argparse.Namespace:
    """
    Parses and returns the command-line arguments for the Caesar Cipher script.
    This function sets up an argument parser to handle various options for encrypting or decrypting text using the Caesar Cipher,
    analyzing character frequencies, and saving results such as frequency tables, plots, and possible shifts.
    Returns:
        argparse.Namespace: An object containing the parsed command-line arguments.
    Arguments:
        --text (str): The text to encrypt and analyze.
        --saveFrecuencyTable (bool): If set, saves the frequency table to a CSV file.
        --savePlots (bool): If set, saves frequency plots for each shift.
        --savePossibleShifts (bool): If set, saves all possible shifts to a txt file.
        --resultsPath (str): Path to save results (default: ../results/caesarCipher).
        --decrypt (bool): If set, decrypts the text instead of encrypting it.
    """

    # Configure the arguments for the script
    parser = argparse.ArgumentParser(
        description="Encrypt text using Caesar Cipher and analyze frequencies.")
    parser.add_argument('--text', type=str,
                        help='The text to encrypt and analyze.')
    parser.add_argument('--saveFrecuencyTable', action='store_true',
                        help='Save the frequency table to a CSV file.')
    parser.add_argument('--savePlots', action='store_true',
                        help='Save frequency plots for each shift.')
    parser.add_argument('--savePossibleShifts', action='store_true',
                        help='Save all possible shifts to a txt file.')
    parser.add_argument('--resultsPath', type=str,
                        default='../results/caesarCipher', help='Path to save results (default: ../results/caesarCipher)')
    parser.add_argument('--decrypt', action='store_true',
                        help='Decrypt the text instead of encrypting it.')
    return parser.parse_args()


def createPlot(frequency, shift, alphabet, resultsPath):
    """
    Creates and saves a bar plot of letter frequencies.
    Args:
        frequency (dict): A dictionary mapping letters to their frequencies.
        shift (int): The shift value associated with the frequency analysis.
        alphabet (list or str): The alphabet used for the frequency analysis.
        resultsPath (str): The directory path where the plot image will be saved.
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(list(alphabet), frequency.values)
    ax.set_title(f'Frequency Analysis for Shift {shift}')
    ax.set_xlabel('Letters')
    ax.set_ylabel('Frequency')
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    plt.tight_layout()  # adjust layout to prevent that the x labels get cut off

    # Use os.path.join for saving plots
    plot_filename = os.path.join(resultsPath, f'frequency_shift_{shift}.png')
    plt.savefig(plot_filename)

    plt.close(fig)  # close the figure to free memory


def cleanText(text) -> str:
    """
    Cleans the input text by performing several normalization steps.
    Steps include:
    - Removing leading and trailing whitespace.
    - Converting the text to lowercase.
    - Replacing newline and carriage return characters with spaces.
    - Replacing multiple consecutive spaces with a single space.
    - Removing any characters that are not lowercase letters or spaces.
    Args:
        text (str): The input string to be cleaned.
    Returns:
        str: The cleaned string.
    """
    
    text = text.strip().lower()
    text = text.replace('\n', ' ').replace('\r', ' ')
    text = re.sub(r'\s{2,}', ' ', text)
    text = re.sub(r'[^a-z\s]', '', text)

    return text


if __name__ == "__main__":

    args = getConsoleArguments()

    if args.text:
        text = args.text
    else:
        text = input("Enter a text to encrypt: ")

    text = cleanText(text)

    if args.saveFrecuencyTable or args.savePlots or args.savePossibleShifts:
        checkPath(os.path.abspath(args.resultsPath))

    cipher = caesarCipher()
    alphabet = 'abcdefghijklmnopqrstuvwxyz'

    frequencyTable = pd.DataFrame(columns=list(alphabet))

    shiftLabels = []
    shiftsFilename = os.path.join(args.resultsPath, 'possible_shifts.txt')

    if args.savePossibleShifts:
        possible_shifts_file = open(shiftsFilename, 'a')

    print(f"All possible shifts for the text '{text}': ")
    for shift in range(1, len(alphabet)):
        cipher.setConfig({'shift': shift, 'alphabet': alphabet})

        newText = cipher.encrypt(
            text) if not args.decrypt else cipher.decrypt(text)

        # Count the frequency of each letter in the encrypted text and added to the frequency table
        frecuency = Counter(newText)

        newRowSeries = pd.Series(0, index=list(alphabet))

        newRowSeries.update(pd.Series(frecuency))

        newRow = pd.DataFrame([newRowSeries])

        frequencyTable = pd.concat([frequencyTable, newRow], ignore_index=True)
        shiftLabels.append(f'Shift {shift}')
        print(f"Shift {shift}: {newText}")

        # if the user wants to save a plot with the frequency of each letter
        if args.savePlots:
            createPlot(newRowSeries, shift, alphabet, args.resultsPath)

        # if the user wants to save all possible shifts in a txt file
        if args.savePossibleShifts:
            possible_shifts_file.write(f"Shift {shift}: {newText}\n")

    # if the user wants to save the frecuency table in a csv file
    if args.saveFrecuencyTable:
        # set the row lables of the frequency table to the shift labels
        frequencyTable.index = shiftLabels

        table_filename = os.path.join(args.resultsPath, 'frequency_table.csv')
        frequencyTable.to_csv(table_filename, index=True)
        print(f"Frequency table saved to '{table_filename}'.")
