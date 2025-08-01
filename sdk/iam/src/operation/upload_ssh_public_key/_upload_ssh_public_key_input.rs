// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UploadSshPublicKeyInput {
    /// <p>The name of the IAM user to associate the SSH public key with.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub user_name: ::std::option::Option<::std::string::String>,
    /// <p>The SSH public key. The public key must be encoded in ssh-rsa format or PEM format. The minimum bit-length of the public key is 2048 bits. For example, you can generate a 2048-bit key, and the resulting PEM file is 1679 bytes long.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    pub ssh_public_key_body: ::std::option::Option<::std::string::String>,
}
impl UploadSshPublicKeyInput {
    /// <p>The name of the IAM user to associate the SSH public key with.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn user_name(&self) -> ::std::option::Option<&str> {
        self.user_name.as_deref()
    }
    /// <p>The SSH public key. The public key must be encoded in ssh-rsa format or PEM format. The minimum bit-length of the public key is 2048 bits. For example, you can generate a 2048-bit key, and the resulting PEM file is 1679 bytes long.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    pub fn ssh_public_key_body(&self) -> ::std::option::Option<&str> {
        self.ssh_public_key_body.as_deref()
    }
}
impl UploadSshPublicKeyInput {
    /// Creates a new builder-style object to manufacture [`UploadSshPublicKeyInput`](crate::operation::upload_ssh_public_key::UploadSshPublicKeyInput).
    pub fn builder() -> crate::operation::upload_ssh_public_key::builders::UploadSshPublicKeyInputBuilder {
        crate::operation::upload_ssh_public_key::builders::UploadSshPublicKeyInputBuilder::default()
    }
}

/// A builder for [`UploadSshPublicKeyInput`](crate::operation::upload_ssh_public_key::UploadSshPublicKeyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UploadSshPublicKeyInputBuilder {
    pub(crate) user_name: ::std::option::Option<::std::string::String>,
    pub(crate) ssh_public_key_body: ::std::option::Option<::std::string::String>,
}
impl UploadSshPublicKeyInputBuilder {
    /// <p>The name of the IAM user to associate the SSH public key with.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    /// This field is required.
    pub fn user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the IAM user to associate the SSH public key with.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn set_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_name = input;
        self
    }
    /// <p>The name of the IAM user to associate the SSH public key with.</p>
    /// <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub fn get_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_name
    }
    /// <p>The SSH public key. The public key must be encoded in ssh-rsa format or PEM format. The minimum bit-length of the public key is 2048 bits. For example, you can generate a 2048-bit key, and the resulting PEM file is 1679 bytes long.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    /// This field is required.
    pub fn ssh_public_key_body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ssh_public_key_body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SSH public key. The public key must be encoded in ssh-rsa format or PEM format. The minimum bit-length of the public key is 2048 bits. For example, you can generate a 2048-bit key, and the resulting PEM file is 1679 bytes long.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    pub fn set_ssh_public_key_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ssh_public_key_body = input;
        self
    }
    /// <p>The SSH public key. The public key must be encoded in ssh-rsa format or PEM format. The minimum bit-length of the public key is 2048 bits. For example, you can generate a 2048-bit key, and the resulting PEM file is 1679 bytes long.</p>
    /// <p>The <a href="http://wikipedia.org/wiki/regex">regex pattern</a> used to validate this parameter is a string of characters consisting of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Any printable ASCII character ranging from the space character (<code>\u0020</code>) through the end of the ASCII character range</p></li>
    /// <li>
    /// <p>The printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>)</p></li>
    /// <li>
    /// <p>The special characters tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>)</p></li>
    /// </ul>
    pub fn get_ssh_public_key_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.ssh_public_key_body
    }
    /// Consumes the builder and constructs a [`UploadSshPublicKeyInput`](crate::operation::upload_ssh_public_key::UploadSshPublicKeyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::upload_ssh_public_key::UploadSshPublicKeyInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::upload_ssh_public_key::UploadSshPublicKeyInput {
            user_name: self.user_name,
            ssh_public_key_body: self.ssh_public_key_body,
        })
    }
}
