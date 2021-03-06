/*
 * RapidMiner Cryptography Extension
 *
 * Copyright (C) 2014-2017 by Nils Woehler
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
package com.rapidminer.cryptography.text;

import java.util.List;

import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

import com.rapidminer.cryptography.PBEncryptorConfigurator;
import com.rapidminer.operator.Operator;
import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.OperatorException;
import com.rapidminer.operator.ProcessSetupError.Severity;
import com.rapidminer.operator.SimpleProcessSetupError;
import com.rapidminer.operator.UserError;
import com.rapidminer.operator.ports.InputPort;
import com.rapidminer.operator.ports.OutputPort;
import com.rapidminer.operator.text.Document;
import com.rapidminer.operator.text.Token;
import com.rapidminer.parameter.ParameterType;
import com.rapidminer.parameter.UndefinedParameterError;

/**
 * The abstract super class for all PBE document encryption/decryption operators.
 * The operator has a document input and a document output. Furthermore the user is able
 * to select the algorithm strength and password.
 * 
 * @author Nils Woehler
 * 
 */
public abstract class AbstractPBDocumentCryptographyOperator extends Operator {

	private static final String DOCUMENT_INPUT = "document_input";
	private static final String DOCUMENT_OUTPUT = "document_output";

	/**
	 * Used to test if encryption works with the current parameters.
	 */
	private static final String RANDOM_TEXT = "This is sparta!";

	private static final PBEncryptorConfigurator ALGORITHM_PROVIDER = new PBEncryptorConfigurator();

	private final InputPort documentInput = getInputPorts().createPort(
			DOCUMENT_INPUT, Document.class);
	private final OutputPort documentOut = getOutputPorts().createPort(
			DOCUMENT_OUTPUT);

	AbstractPBDocumentCryptographyOperator(OperatorDescription description) {
		super(description);
		
		getTransformer().addRule(() -> {
			try {
				PBEStringEncryptor encryptor = configureEncryptor();
				encryptor.decrypt(encryptor.encrypt(RANDOM_TEXT));
			} catch (Throwable t) {
				addError(new SimpleProcessSetupError(Severity.ERROR,
						getPortOwner(), "text.encryption_error", t
								.getLocalizedMessage()));
			}
		});
		getTransformer().addPassThroughRule(documentInput, documentOut);
	}

	@Override
	public void doWork() throws OperatorException {

		// retrieve document
		Document input = documentInput.getData(Document.class);

		// encrypt/decrypt text
		String text = transformText(configureEncryptor(), getText(input));

		// deliver transformed document
		documentOut.deliver(new Document(text));
	}

	private String getText(Document input) {
		StringBuilder builder = new StringBuilder();
		List<Token> tokenSequence = input.getTokenSequence();
		for(Token token : tokenSequence) {
			builder.append(token.getToken());
			builder.append(" ");
		}
		return builder.toString().trim();
	}

	/**
	 * Creates and configures a string encryptor.
	 */
	private PBEStringEncryptor configureEncryptor()
			throws UndefinedParameterError {
		return ALGORITHM_PROVIDER.configureStringEncryptor(this);
	}

	/**
	 * Transforms the input, e.g. encrypts or decrypts it with the provided
	 * {@link StandardPBEStringEncryptor}.
	 * 
	 * @param encryptor
	 *            the encryptor being used
	 * @param text
	 *            the text being encrypted/decrypted
	 * @return the encrypted/decrypted content
	 */
	protected abstract String transformText(PBEStringEncryptor encryptor, String text) throws UserError;

	@Override
	public List<ParameterType> getParameterTypes() {
		List<ParameterType> parameterTypes = super.getParameterTypes();
		parameterTypes.addAll(ALGORITHM_PROVIDER.getParameterTypes(this));
		return parameterTypes;
	}
}
