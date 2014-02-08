/*
 *  RapidMiner Encryption Extension
 *
 *  Copyright (C) 2014 by Nils Wöhler
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
package com.rapidminer.operator.text;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.UserError;

/**
 * An operator for encrypting documents.
 * 
 * @author Nils Woehler
 * 
 */
public class PBDocumentEncryptionOperator extends
		AbstractPBDocumentEncryptionOperator {

	public PBDocumentEncryptionOperator(OperatorDescription description) {
		super(description);
	}

	@Override
	protected String transformText(StandardPBEStringEncryptor encryptor,
			String text) throws UserError {
		try {
			return encryptor.encrypt(text);
		} catch (EncryptionOperationNotPossibleException e) {
			throw new UserError(this, e, "text.encryption_not_possible");
		}
	}

}
