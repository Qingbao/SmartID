package smartid.hig.no.gui;

/**
 * A class reflect the format of a field for entering data. The set of
 * characters can be limited (e.g. only letters or digits, the minimum and
 * maximum length). For int fields also a minimum and maximum values can be set.
 *
 *
 */
public class FieldFormat {

	public static final int LETTERS = 1;

	public static final int DIGITS = 2;

	public static final int SYMBOL = 4;

	int characters;

	int minLength, maxLength;

	int minValue = -1, maxValue = -1;

	int requiredNumOfSemi = -1;

	/**
	 * A constructor for category.
	 *
	 * @param category true
	 */
	public FieldFormat(boolean category) {
		if (!category) {
			throw new IllegalArgumentException();
		}
		this.maxLength = 30;
	}

	/**
	 * A constructor for a fixed length field.
	 *
	 * @param characters a mask with allowed characters
	 * @param fixedLength the length of the field (fixed=min=max)
	 */
	public FieldFormat(int characters, int fixedLength) {
		this(characters, fixedLength, fixedLength);
	}

	/**
	 * A constructor for variable length field.
	 *
	 * @param characters a mask with allowed characters
	 * @param minLength min length of the string
	 * @param maxLength max length of the string
	 */
	public FieldFormat(int characters, int minLength, int maxLength) {
		this(characters, minLength, maxLength, -1, -1, -1);
	}

	/**
	 * A constructor for a fixed length int field.
	 *
	 * @param characters a mask with allowed characters (should be DIGITS)
	 * @param fixedLength the length of the field (fixed=min=max)
	 * @param minValue min value
	 * @param maxValue max value
	 */
	public FieldFormat(int characters, int fixedLength, int minValue,
			int maxValue) {
		this(characters, fixedLength, fixedLength, minValue, maxValue, -1);
	}

	/**
	 * Costructor
	 *
	 * @param characters a mask with allowed characters
	 * @param minLength min length of the field
	 * @param maxLength max length of the field
	 * @param minValue min value of the (int) field
	 * @param maxValue max value of the (int) field
	 */
	public FieldFormat(int characters, int minLength, int maxLength,
			int minValue, int maxValue) {
		this(characters, minLength, maxLength, minValue, maxValue, -1);
	}

	/**
	 * The general costructor
	 *
	 * @param characters a mask with allowed characters
	 * @param minLength min length of the field
	 * @param maxLength max length of the field
	 * @param minValue min value of the (int) field
	 * @param maxValue max value of the (int) field
	 * @param semiNum the number of required semicolons
	 */
	public FieldFormat(int characters, int minLength, int maxLength,
			int minValue, int maxValue, int semiNum) {
		this.characters = characters;
		this.minLength = minLength;
		this.maxLength = maxLength;
		this.minValue = minValue;
		this.maxValue = maxValue;
		this.requiredNumOfSemi = semiNum;

	}

	/**
	 * Returns a help string for a descriptive tool-tip text
	 *
	 * @return a help string for a descriptive tool-tip text
	 */
	String getHelpText() {

		boolean letters = ((characters & LETTERS) == LETTERS);
		boolean digits = ((characters & DIGITS) == DIGITS);
		boolean ascii = ((characters & SYMBOL) == SYMBOL);
		return "Allowed characters:"
				+ (letters ? " letters" : " ")
				+ (digits ? " digits" : " ")
				+ (ascii ? " ascii" : " ")
				+ " \nminimum length: "
				+ minLength
				+ " maximum length: "
				+ maxLength
				+ (minValue != -1 ? " \nminimum value: " + minValue
						+ " maximum value: " + maxValue : "")
				+ (requiredNumOfSemi != -1 ? ",\n " + (requiredNumOfSemi + 1) + " \';\' separated fields" : "");
	}

	/**
	 * Verfies if the input string is correct accoring to the field
	 * specification stored in this object.
	 *
	 * @param input the input string
	 * @return true if the input is correct, false otherwise
	 */
	boolean isCorrectInput(String input) {

		int len = input.length();
		if (len < minLength || len > maxLength) {
			return false;
		}
		boolean letters = ((characters & LETTERS) == LETTERS);
		boolean digits = ((characters & DIGITS) == DIGITS);
		boolean ascii = ((characters & SYMBOL) == SYMBOL);
		int semi = 0;
		for (int i = 0; i < len; i++) {
			char c = input.charAt(i);
			if (c == ';') {
				semi++;
			}
			if ((Character.isLetter(c) && !letters)
					|| (Character.isDigit(c) && !digits)
					|| (isSymbol(c) && !ascii)) {
				return false;
			}
		}
		if (characters == DIGITS && minValue != -1 && maxValue != -1) {
			try {
				int i = Integer.parseInt(input);
				if (i < minValue || i > maxValue) {
					return false;
				}
			} catch (NumberFormatException nfe) {
				return false;
			}
		}
		if (requiredNumOfSemi >= 0 && semi != requiredNumOfSemi) {
			return false;
		}
		return true;
	}

	public static boolean isSymbol(char c) {
		return (c >= 32 && c <= 47) || (c >= 58 && c <= 64);
	}

}
