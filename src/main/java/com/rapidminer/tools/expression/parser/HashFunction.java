/*
 *  RapidMiner Cryptography Extension
 *
 *  Copyright (C) 2014 by Nils Woehler
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see http://www.gnu.org/licenses/.
 */
package com.rapidminer.tools.expression.parser;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Date;

import org.jasypt.contrib.org.apache.commons.codec_1_3.binary.Base64;
import org.jasypt.digest.StandardByteDigester;

import com.rapidminer.BCProvider;

/**
 * 
 * A JEP function that calculate the hash value of the provided input.
 * 
 * @author Nils Woehler
 * 
 */
public class HashFunction implements Function {

	// BASE64 encoder which will make sure the returned digests are
	// valid US-ASCII strings.
	// The Base64 encoder is THREAD-SAFE
	private static final Base64 BASE64 = new Base64();

	// Charset to
	public static final String DIGEST_CHARSET = "US-ASCII";

	/**
	 * The name used as RapidMiner function.
	 */
	private final String functionName;

	/**
	 * The function ID used to select the algorithm from the algorithm provider.
	 */
	private final String functionID;

	public HashFunction(String functionID) {
		this.functionID = functionID;
		this.functionName = functionID.replace("-", "").toLowerCase();
	}

	@Override
	public Object compute(Object... arguments) throws JEPFunctionException {
		StandardByteDigester digester = new StandardByteDigester();
		digester.setAlgorithm(functionID);
		digester.setProvider(BCProvider.INSTANCE.get());
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				DataOutputStream dos = new DataOutputStream(baos);) {

			int messageIndex = 0;
			switch (arguments.length) {
			case 0:
				throw new JEPFunctionException("No input defined");
			case 1:
				// only message as input
				break;
			case 2:
				// salt size defined
				messageIndex = 1;
				configureSaltSize(digester, 0, arguments);
				break;
			case 3:
				// salt size and number of iterations defined
				messageIndex = 2;
				configureNumberOfIterations(digester, 0, arguments);
				configureSaltSize(digester, 1, arguments);
				break;
			default:
				throw new JEPFunctionException("Too many arguments. For "
						+ functionName + " only three arguments are supported.");

			}
			return new String(BASE64.encode(digester.digest(getBytes(baos, dos,
					messageIndex, arguments))), DIGEST_CHARSET);
		} catch (Throwable t) {
			throw new JEPFunctionException("Error calculating " + functionID
					+ " hash value: " + t.getLocalizedMessage());
		}
	}

	private void configureNumberOfIterations(StandardByteDigester digester,
			int index, Object... arguments) throws JEPFunctionException {
		Object arg2 = arguments[index];
		Integer numberOfIterations = 1;
		if (arg2 instanceof Number) {
			numberOfIterations = ((Number) arg2).intValue();
		} else {
			throw new JEPFunctionException(
					"Wrong input type for number of iterations argument. Only numbers are allowed.");
		}
		if (numberOfIterations < 1) {
			throw new JEPFunctionException(
					"The number of iterations has to be >= 1. Specified number of iterations: "
							+ numberOfIterations);
		}
		digester.setIterations(numberOfIterations);
	}

	private void configureSaltSize(StandardByteDigester digester, int index,
			Object... arguments) throws JEPFunctionException {
		Object arg1 = arguments[index];
		Integer saltSize = 8;
		if (arg1 instanceof Number) {
			saltSize = ((Number) arg1).intValue();
		} else {
			throw new JEPFunctionException(
					"Wrong input type for salt size argument. Only numbers are allowed.");
		}
		if (saltSize < 0) {
			throw new JEPFunctionException("The salt size has to be >= 0. "
					+ "Specified salt size: " + saltSize);
		}
		digester.setSaltSizeBytes(saltSize);
	}

	private byte[] getBytes(ByteArrayOutputStream baos, DataOutputStream dos,
			int index, Object... arguments) throws IOException {
		Object value = arguments[index];
		if (value instanceof String) {
			dos.writeUTF((String) value);
		} else if (value instanceof Integer) {
			dos.writeInt((int) value);
		} else if (value instanceof Long) {
			dos.writeLong((long) value);
		} else if (value instanceof Float) {
			dos.writeFloat((float) value);
		} else if (value instanceof Date) {
			dos.writeLong(((Date) value).getTime());
		} else if (value instanceof Double) {
			dos.writeDouble((double) value);
		}
		return baos.toByteArray();
	}

	@Override
	public FunctionDescription getFunctionDescription() {
		return new FunctionDescription(
				functionName,
				functionName,
				"<html><br/>Calculates the BASE64 encoded "
						+ functionID
						+ " hash value of the provided input.<b>If the number of salt bytes is not changed via the second parameter two hashes "
						+ "<br/> created for the same input will always be different</b>. "
						+ "To check whether two hashes are equal use 'match"
						+ functionName
						+ "'. "
						+ "<ul>"
						+ "<li>The first parameter defines the input for which the hash value should be calculated. </li>"
						+ "<li>The second parameter is optional and defines the number of bytes that should be used as salt (Default: 8, Minimum: 1). If it is set to zero no salt will be used.</li>"
						+ "<li>The third parameter is optional and defines the number of iterations (Minimum: 1).</li>"
						+ "</ul><html>",
				FunctionDescription.UNLIMITED_NUMBER_OF_ARGUMENTS);
	}

	@Override
	public String getFunctionName() {
		return functionName;
	}

}
