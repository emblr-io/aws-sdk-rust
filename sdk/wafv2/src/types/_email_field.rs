// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The name of the field in the request payload that contains your customer's email.</p>
/// <p>This data type is used in the <code>RequestInspectionACFP</code> data type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EmailField {
    /// <p>The name of the email field.</p>
    /// <p>How you specify this depends on the request inspection payload type.</p>
    /// <ul>
    /// <li>
    /// <p>For JSON payloads, specify the field name in JSON pointer syntax. For information about the JSON Pointer syntax, see the Internet Engineering Task Force (IETF) documentation <a href="https://tools.ietf.org/html/rfc6901">JavaScript Object Notation (JSON) Pointer</a>.</p>
    /// <p>For example, for the JSON payload <code>{ "form": { "email": "THE_EMAIL" } }</code>, the email field specification is <code>/form/email</code>.</p></li>
    /// <li>
    /// <p>For form encoded payload types, use the HTML form names.</p>
    /// <p>For example, for an HTML form with the input element named <code>email1</code>, the email field specification is <code>email1</code>.</p></li>
    /// </ul>
    pub identifier: ::std::string::String,
}
impl EmailField {
    /// <p>The name of the email field.</p>
    /// <p>How you specify this depends on the request inspection payload type.</p>
    /// <ul>
    /// <li>
    /// <p>For JSON payloads, specify the field name in JSON pointer syntax. For information about the JSON Pointer syntax, see the Internet Engineering Task Force (IETF) documentation <a href="https://tools.ietf.org/html/rfc6901">JavaScript Object Notation (JSON) Pointer</a>.</p>
    /// <p>For example, for the JSON payload <code>{ "form": { "email": "THE_EMAIL" } }</code>, the email field specification is <code>/form/email</code>.</p></li>
    /// <li>
    /// <p>For form encoded payload types, use the HTML form names.</p>
    /// <p>For example, for an HTML form with the input element named <code>email1</code>, the email field specification is <code>email1</code>.</p></li>
    /// </ul>
    pub fn identifier(&self) -> &str {
        use std::ops::Deref;
        self.identifier.deref()
    }
}
impl EmailField {
    /// Creates a new builder-style object to manufacture [`EmailField`](crate::types::EmailField).
    pub fn builder() -> crate::types::builders::EmailFieldBuilder {
        crate::types::builders::EmailFieldBuilder::default()
    }
}

/// A builder for [`EmailField`](crate::types::EmailField).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EmailFieldBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl EmailFieldBuilder {
    /// <p>The name of the email field.</p>
    /// <p>How you specify this depends on the request inspection payload type.</p>
    /// <ul>
    /// <li>
    /// <p>For JSON payloads, specify the field name in JSON pointer syntax. For information about the JSON Pointer syntax, see the Internet Engineering Task Force (IETF) documentation <a href="https://tools.ietf.org/html/rfc6901">JavaScript Object Notation (JSON) Pointer</a>.</p>
    /// <p>For example, for the JSON payload <code>{ "form": { "email": "THE_EMAIL" } }</code>, the email field specification is <code>/form/email</code>.</p></li>
    /// <li>
    /// <p>For form encoded payload types, use the HTML form names.</p>
    /// <p>For example, for an HTML form with the input element named <code>email1</code>, the email field specification is <code>email1</code>.</p></li>
    /// </ul>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the email field.</p>
    /// <p>How you specify this depends on the request inspection payload type.</p>
    /// <ul>
    /// <li>
    /// <p>For JSON payloads, specify the field name in JSON pointer syntax. For information about the JSON Pointer syntax, see the Internet Engineering Task Force (IETF) documentation <a href="https://tools.ietf.org/html/rfc6901">JavaScript Object Notation (JSON) Pointer</a>.</p>
    /// <p>For example, for the JSON payload <code>{ "form": { "email": "THE_EMAIL" } }</code>, the email field specification is <code>/form/email</code>.</p></li>
    /// <li>
    /// <p>For form encoded payload types, use the HTML form names.</p>
    /// <p>For example, for an HTML form with the input element named <code>email1</code>, the email field specification is <code>email1</code>.</p></li>
    /// </ul>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The name of the email field.</p>
    /// <p>How you specify this depends on the request inspection payload type.</p>
    /// <ul>
    /// <li>
    /// <p>For JSON payloads, specify the field name in JSON pointer syntax. For information about the JSON Pointer syntax, see the Internet Engineering Task Force (IETF) documentation <a href="https://tools.ietf.org/html/rfc6901">JavaScript Object Notation (JSON) Pointer</a>.</p>
    /// <p>For example, for the JSON payload <code>{ "form": { "email": "THE_EMAIL" } }</code>, the email field specification is <code>/form/email</code>.</p></li>
    /// <li>
    /// <p>For form encoded payload types, use the HTML form names.</p>
    /// <p>For example, for an HTML form with the input element named <code>email1</code>, the email field specification is <code>email1</code>.</p></li>
    /// </ul>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`EmailField`](crate::types::EmailField).
    /// This method will fail if any of the following fields are not set:
    /// - [`identifier`](crate::types::builders::EmailFieldBuilder::identifier)
    pub fn build(self) -> ::std::result::Result<crate::types::EmailField, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EmailField {
            identifier: self.identifier.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "identifier",
                    "identifier was not specified but it is required when building EmailField",
                )
            })?,
        })
    }
}
