package com.rapidminer.operator.text;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.UserError;

/**
 * Encrypts files.
 * 
 * @author Nils Woehler
 * 
 */
public class EncryptDocumentOperator extends AbstractDocumentEncryptorOperator {

	public EncryptDocumentOperator(OperatorDescription description) {
		super(description);
	}

	@Override
	protected String transformText(StandardPBEStringEncryptor encryptor,
			String text) throws UserError {
		return encryptor.encrypt(text);
	}

}
