// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDatabaseInput {
    /// <p>The name of the database.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the new KMS key (<code>KmsKeyId</code>) to be used to encrypt the data stored in the database. If the <code>KmsKeyId</code> currently registered with the database is the same as the <code>KmsKeyId</code> in the request, there will not be any update.</p>
    /// <p>You can specify the <code>KmsKeyId</code> using any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Alias name: <code>alias/ExampleAlias</code></p></li>
    /// <li>
    /// <p>Alias ARN: <code>arn:aws:kms:us-east-1:111122223333:alias/ExampleAlias</code></p></li>
    /// </ul>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
}
impl UpdateDatabaseInput {
    /// <p>The name of the database.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
    /// <p>The identifier of the new KMS key (<code>KmsKeyId</code>) to be used to encrypt the data stored in the database. If the <code>KmsKeyId</code> currently registered with the database is the same as the <code>KmsKeyId</code> in the request, there will not be any update.</p>
    /// <p>You can specify the <code>KmsKeyId</code> using any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Alias name: <code>alias/ExampleAlias</code></p></li>
    /// <li>
    /// <p>Alias ARN: <code>arn:aws:kms:us-east-1:111122223333:alias/ExampleAlias</code></p></li>
    /// </ul>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
}
impl UpdateDatabaseInput {
    /// Creates a new builder-style object to manufacture [`UpdateDatabaseInput`](crate::operation::update_database::UpdateDatabaseInput).
    pub fn builder() -> crate::operation::update_database::builders::UpdateDatabaseInputBuilder {
        crate::operation::update_database::builders::UpdateDatabaseInputBuilder::default()
    }
}

/// A builder for [`UpdateDatabaseInput`](crate::operation::update_database::UpdateDatabaseInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDatabaseInputBuilder {
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
}
impl UpdateDatabaseInputBuilder {
    /// <p>The name of the database.</p>
    /// This field is required.
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the database.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The name of the database.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>The identifier of the new KMS key (<code>KmsKeyId</code>) to be used to encrypt the data stored in the database. If the <code>KmsKeyId</code> currently registered with the database is the same as the <code>KmsKeyId</code> in the request, there will not be any update.</p>
    /// <p>You can specify the <code>KmsKeyId</code> using any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Alias name: <code>alias/ExampleAlias</code></p></li>
    /// <li>
    /// <p>Alias ARN: <code>arn:aws:kms:us-east-1:111122223333:alias/ExampleAlias</code></p></li>
    /// </ul>
    /// This field is required.
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the new KMS key (<code>KmsKeyId</code>) to be used to encrypt the data stored in the database. If the <code>KmsKeyId</code> currently registered with the database is the same as the <code>KmsKeyId</code> in the request, there will not be any update.</p>
    /// <p>You can specify the <code>KmsKeyId</code> using any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Alias name: <code>alias/ExampleAlias</code></p></li>
    /// <li>
    /// <p>Alias ARN: <code>arn:aws:kms:us-east-1:111122223333:alias/ExampleAlias</code></p></li>
    /// </ul>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The identifier of the new KMS key (<code>KmsKeyId</code>) to be used to encrypt the data stored in the database. If the <code>KmsKeyId</code> currently registered with the database is the same as the <code>KmsKeyId</code> in the request, there will not be any update.</p>
    /// <p>You can specify the <code>KmsKeyId</code> using any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Alias name: <code>alias/ExampleAlias</code></p></li>
    /// <li>
    /// <p>Alias ARN: <code>arn:aws:kms:us-east-1:111122223333:alias/ExampleAlias</code></p></li>
    /// </ul>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// Consumes the builder and constructs a [`UpdateDatabaseInput`](crate::operation::update_database::UpdateDatabaseInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_database::UpdateDatabaseInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_database::UpdateDatabaseInput {
            database_name: self.database_name,
            kms_key_id: self.kms_key_id,
        })
    }
}
