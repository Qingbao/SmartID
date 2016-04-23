/**
 *
 */
package smartid.hig.no.services;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Encapsulates basic info, i.e. DG1
 *
 *
 *
 */
public class BasicInfo {

	public String sur = null;

	public String given = null;

	public String gender = null;

	public String dob = null;

	public String pob = null;

	public String issue = null;

	public String expriy = null;

	public String country = null;

	public String authority = null;

	public String id = null;

	public BasicInfo(String sur, String given, String gender, String dob,
			String pob, String issue, String expriy, String country,
			String authority, String id) {
		this.sur = sur;
		this.given = given;
		this.gender = gender;
		this.dob = dob;
		this.pob = pob;
		this.issue = issue;
		this.expriy = expriy;
		this.country = country;
		this.authority = authority;
		this.id = id;
	}

	/**
	 * Constructs a new file based on data in <code>in</code>.
	 *
	 * @param in the input stream to be decoded
	 *
	 * @throws IOException if decoding fails
	 */
	public BasicInfo(InputStream in) throws IOException {
		int len = 0;
		byte[] t = null;
		len = in.read();

		t = new byte[len];
		in.read(t);
		sur = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		given = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		gender = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		dob = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		pob = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		issue = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		expriy = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		country = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		authority = new String(t);

		len = in.read();
		t = new byte[len];
		in.read(t);
		id = new String(t);

	}

	public String toString() {
		return sur + "<" + given + "<" + gender + "<" + dob + "<" + pob + "<"
				+ issue + "<" + expriy + "<" + country + "<" + authority + "<"
				+ id;
	}

	/**
	 * Gets the encoded version of this file.
	 */
	public byte[] getEncoded() {
		String[] data = {sur, given, gender, dob, pob, issue, expriy, country,
			authority, id};
		int total = 0;
		for (String s : data) {
			total += s.length() + 1;
		}
		byte[] result = new byte[total];
		int offset = 0;
		for (String s : data) {
			result[offset++] = (byte) s.length();
			System.arraycopy(s.getBytes(), 0, result, offset, s.length());
			offset += s.length();
		}

		return result;
	}

	// test
	public static void main(String[] args) throws IOException {
		String a = "surname";
		String b = "givenname";
		String c = "gender";
		String d = "dob";
		String e = "dop";
		String f = "issue";
		String g = "expriy";
		String h = "country";
		String i = "authority";
		String j = "id";

		BasicInfo basic = new BasicInfo(a, b, c, d, e, f, g, h, i, j);

		byte[] result = basic.getEncoded();

		System.out.println(basic.toString());

		InputStream in = new ByteArrayInputStream(result);

		BasicInfo basic2 = new BasicInfo(in);

		System.out.println(basic2.toString());

	}

}
