// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The user-specified message system attribute value. For string data types, the <code>Value</code> attribute has the same restrictions on the content as the message body. For more information, see <code> <code>SendMessage</code>.</code></p>
/// <p><code>Name</code>, <code>type</code>, <code>value</code> and the message body must not be empty or null.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MessageSystemAttributeValue {
    /// <p>Strings are Unicode with UTF-8 binary encoding. For a list of code values, see <a href="http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters">ASCII Printable Characters</a>.</p>
    pub string_value: ::std::option::Option<::std::string::String>,
    /// <p>Binary type attributes can store any binary data, such as compressed data, encrypted data, or images.</p>
    pub binary_value: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>Not implemented. Reserved for future use.</p>
    pub string_list_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Not implemented. Reserved for future use.</p>
    pub binary_list_values: ::std::option::Option<::std::vec::Vec<::aws_smithy_types::Blob>>,
    /// <p>Amazon SQS supports the following logical data types: <code>String</code>, <code>Number</code>, and <code>Binary</code>. For the <code>Number</code> data type, you must use <code>StringValue</code>.</p>
    /// <p>You can also append custom labels. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html#sqs-message-attributes">Amazon SQS Message Attributes</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub data_type: ::std::string::String,
}
impl MessageSystemAttributeValue {
    /// <p>Strings are Unicode with UTF-8 binary encoding. For a list of code values, see <a href="http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters">ASCII Printable Characters</a>.</p>
    pub fn string_value(&self) -> ::std::option::Option<&str> {
        self.string_value.as_deref()
    }
    /// <p>Binary type attributes can store any binary data, such as compressed data, encrypted data, or images.</p>
    pub fn binary_value(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.binary_value.as_ref()
    }
    /// <p>Not implemented. Reserved for future use.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.string_list_values.is_none()`.
    pub fn string_list_values(&self) -> &[::std::string::String] {
        self.string_list_values.as_deref().unwrap_or_default()
    }
    /// <p>Not implemented. Reserved for future use.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.binary_list_values.is_none()`.
    pub fn binary_list_values(&self) -> &[::aws_smithy_types::Blob] {
        self.binary_list_values.as_deref().unwrap_or_default()
    }
    /// <p>Amazon SQS supports the following logical data types: <code>String</code>, <code>Number</code>, and <code>Binary</code>. For the <code>Number</code> data type, you must use <code>StringValue</code>.</p>
    /// <p>You can also append custom labels. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html#sqs-message-attributes">Amazon SQS Message Attributes</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub fn data_type(&self) -> &str {
        use std::ops::Deref;
        self.data_type.deref()
    }
}
impl MessageSystemAttributeValue {
    /// Creates a new builder-style object to manufacture [`MessageSystemAttributeValue`](crate::types::MessageSystemAttributeValue).
    pub fn builder() -> crate::types::builders::MessageSystemAttributeValueBuilder {
        crate::types::builders::MessageSystemAttributeValueBuilder::default()
    }
}

/// A builder for [`MessageSystemAttributeValue`](crate::types::MessageSystemAttributeValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MessageSystemAttributeValueBuilder {
    pub(crate) string_value: ::std::option::Option<::std::string::String>,
    pub(crate) binary_value: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) string_list_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) binary_list_values: ::std::option::Option<::std::vec::Vec<::aws_smithy_types::Blob>>,
    pub(crate) data_type: ::std::option::Option<::std::string::String>,
}
impl MessageSystemAttributeValueBuilder {
    /// <p>Strings are Unicode with UTF-8 binary encoding. For a list of code values, see <a href="http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters">ASCII Printable Characters</a>.</p>
    pub fn string_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.string_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Strings are Unicode with UTF-8 binary encoding. For a list of code values, see <a href="http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters">ASCII Printable Characters</a>.</p>
    pub fn set_string_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.string_value = input;
        self
    }
    /// <p>Strings are Unicode with UTF-8 binary encoding. For a list of code values, see <a href="http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters">ASCII Printable Characters</a>.</p>
    pub fn get_string_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.string_value
    }
    /// <p>Binary type attributes can store any binary data, such as compressed data, encrypted data, or images.</p>
    pub fn binary_value(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.binary_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>Binary type attributes can store any binary data, such as compressed data, encrypted data, or images.</p>
    pub fn set_binary_value(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.binary_value = input;
        self
    }
    /// <p>Binary type attributes can store any binary data, such as compressed data, encrypted data, or images.</p>
    pub fn get_binary_value(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.binary_value
    }
    /// Appends an item to `string_list_values`.
    ///
    /// To override the contents of this collection use [`set_string_list_values`](Self::set_string_list_values).
    ///
    /// <p>Not implemented. Reserved for future use.</p>
    pub fn string_list_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.string_list_values.unwrap_or_default();
        v.push(input.into());
        self.string_list_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Not implemented. Reserved for future use.</p>
    pub fn set_string_list_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.string_list_values = input;
        self
    }
    /// <p>Not implemented. Reserved for future use.</p>
    pub fn get_string_list_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.string_list_values
    }
    /// Appends an item to `binary_list_values`.
    ///
    /// To override the contents of this collection use [`set_binary_list_values`](Self::set_binary_list_values).
    ///
    /// <p>Not implemented. Reserved for future use.</p>
    pub fn binary_list_values(mut self, input: ::aws_smithy_types::Blob) -> Self {
        let mut v = self.binary_list_values.unwrap_or_default();
        v.push(input);
        self.binary_list_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Not implemented. Reserved for future use.</p>
    pub fn set_binary_list_values(mut self, input: ::std::option::Option<::std::vec::Vec<::aws_smithy_types::Blob>>) -> Self {
        self.binary_list_values = input;
        self
    }
    /// <p>Not implemented. Reserved for future use.</p>
    pub fn get_binary_list_values(&self) -> &::std::option::Option<::std::vec::Vec<::aws_smithy_types::Blob>> {
        &self.binary_list_values
    }
    /// <p>Amazon SQS supports the following logical data types: <code>String</code>, <code>Number</code>, and <code>Binary</code>. For the <code>Number</code> data type, you must use <code>StringValue</code>.</p>
    /// <p>You can also append custom labels. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html#sqs-message-attributes">Amazon SQS Message Attributes</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    /// This field is required.
    pub fn data_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon SQS supports the following logical data types: <code>String</code>, <code>Number</code>, and <code>Binary</code>. For the <code>Number</code> data type, you must use <code>StringValue</code>.</p>
    /// <p>You can also append custom labels. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html#sqs-message-attributes">Amazon SQS Message Attributes</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub fn set_data_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_type = input;
        self
    }
    /// <p>Amazon SQS supports the following logical data types: <code>String</code>, <code>Number</code>, and <code>Binary</code>. For the <code>Number</code> data type, you must use <code>StringValue</code>.</p>
    /// <p>You can also append custom labels. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-metadata.html#sqs-message-attributes">Amazon SQS Message Attributes</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub fn get_data_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_type
    }
    /// Consumes the builder and constructs a [`MessageSystemAttributeValue`](crate::types::MessageSystemAttributeValue).
    /// This method will fail if any of the following fields are not set:
    /// - [`data_type`](crate::types::builders::MessageSystemAttributeValueBuilder::data_type)
    pub fn build(self) -> ::std::result::Result<crate::types::MessageSystemAttributeValue, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MessageSystemAttributeValue {
            string_value: self.string_value,
            binary_value: self.binary_value,
            string_list_values: self.string_list_values,
            binary_list_values: self.binary_list_values,
            data_type: self.data_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_type",
                    "data_type was not specified but it is required when building MessageSystemAttributeValue",
                )
            })?,
        })
    }
}
