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

import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.UserError;

/**
 * An operator for decrypting documents.
 * 
 * @author Nils Woehler
 * 
 */
public class PBDocumentDecryptionOperator extends AbstractPBDocumentCryptographyOperator {

	public PBDocumentDecryptionOperator(OperatorDescription description) {
		super(description);
	}

	@Override
	protected String transformText(PBEStringEncryptor encryptor,
			String text) throws UserError {
		try {
			return encryptor.decrypt(text);
		} catch (EncryptionOperationNotPossibleException e) {
			throw new UserError(this, "text.decryption_failed"); 
		}
	}

}