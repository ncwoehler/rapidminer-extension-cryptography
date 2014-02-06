package com.rapidminer.operator.nio.file;

import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

import com.rapidminer.operator.OperatorDescription;

/**
 * Encrypts files.
 * 
 * @author Nils Woehler
 * 
 */
public class PBFileEncryptionOperator extends AbstractPBFileEncryptionOperator {

	public PBFileEncryptionOperator(OperatorDescription description) {
		super(description);
	}

	@Override
	protected byte[] transformFile(StandardPBEByteEncryptor encryptor,
			byte[] fileContent) {
		return encryptor.encrypt(fileContent);
	}

}
