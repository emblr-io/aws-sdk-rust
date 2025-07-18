// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that defines the email template to use for an email message, and the values to use for any message variables in that template. An <i>email template</i> is a type of message template that contains content that you want to reuse in email messages that you send. You can specifiy the email template by providing the name or ARN of an <i>email template</i> previously saved in your Amazon SES account or by providing the full template content.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Template {
    /// <p>The name of the template. You will refer to this name when you send email using the <code>SendEmail</code> or <code>SendBulkEmail</code> operations.</p>
    pub template_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the template.</p>
    pub template_arn: ::std::option::Option<::std::string::String>,
    /// <p>The content of the template.</p><note>
    /// <p>Amazon SES supports only simple substitions when you send email using the <code>SendEmail</code> or <code>SendBulkEmail</code> operations and you provide the full template content in the request.</p>
    /// </note>
    pub template_content: ::std::option::Option<crate::types::EmailTemplateContent>,
    /// <p>An object that defines the values to use for message variables in the template. This object is a set of key-value pairs. Each key defines a message variable in the template. The corresponding value defines the value to use for that variable.</p>
    pub template_data: ::std::option::Option<::std::string::String>,
    /// <p>The list of message headers that will be added to the email message.</p>
    pub headers: ::std::option::Option<::std::vec::Vec<crate::types::MessageHeader>>,
    /// <p>The List of attachments to include in your email. All recipients will receive the same attachments.</p>
    pub attachments: ::std::option::Option<::std::vec::Vec<crate::types::Attachment>>,
}
impl Template {
    /// <p>The name of the template. You will refer to this name when you send email using the <code>SendEmail</code> or <code>SendBulkEmail</code> operations.</p>
    pub fn template_name(&self) -> ::std::option::Option<&str> {
        self.template_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the template.</p>
    pub fn template_arn(&self) -> ::std::option::Option<&str> {
        self.template_arn.as_deref()
    }
    /// <p>The content of the template.</p><note>
    /// <p>Amazon SES supports only simple substitions when you send email using the <code>SendEmail</code> or <code>SendBulkEmail</code> operations and you provide the full template content in the request.</p>
    /// </note>
    pub fn template_content(&self) -> ::std::option::Option<&crate::types::EmailTemplateContent> {
        self.template_content.as_ref()
    }
    /// <p>An object that defines the values to use for message variables in the template. This object is a set of key-value pairs. Each key defines a message variable in the template. The corresponding value defines the value to use for that variable.</p>
    pub fn template_data(&self) -> ::std::option::Option<&str> {
        self.template_data.as_deref()
    }
    /// <p>The list of message headers that will be added to the email message.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.headers.is_none()`.
    pub fn headers(&self) -> &[crate::types::MessageHeader] {
        self.headers.as_deref().unwrap_or_default()
    }
    /// <p>The List of attachments to include in your email. All recipients will receive the same attachments.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attachments.is_none()`.
    pub fn attachments(&self) -> &[crate::types::Attachment] {
        self.attachments.as_deref().unwrap_or_default()
    }
}
impl Template {
    /// Creates a new builder-style object to manufacture [`Template`](crate::types::Template).
    pub fn builder() -> crate::types::builders::TemplateBuilder {
        crate::types::builders::TemplateBuilder::default()
    }
}

/// A builder for [`Template`](crate::types::Template).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TemplateBuilder {
    pub(crate) template_name: ::std::option::Option<::std::string::String>,
    pub(crate) template_arn: ::std::option::Option<::std::string::String>,
    pub(crate) template_content: ::std::option::Option<crate::types::EmailTemplateContent>,
    pub(crate) template_data: ::std::option::Option<::std::string::String>,
    pub(crate) headers: ::std::option::Option<::std::vec::Vec<crate::types::MessageHeader>>,
    pub(crate) attachments: ::std::option::Option<::std::vec::Vec<crate::types::Attachment>>,
}
impl TemplateBuilder {
    /// <p>The name of the template. You will refer to this name when you send email using the <code>SendEmail</code> or <code>SendBulkEmail</code> operations.</p>
    pub fn template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the template. You will refer to this name when you send email using the <code>SendEmail</code> or <code>SendBulkEmail</code> operations.</p>
    pub fn set_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_name = input;
        self
    }
    /// <p>The name of the template. You will refer to this name when you send email using the <code>SendEmail</code> or <code>SendBulkEmail</code> operations.</p>
    pub fn get_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_name
    }
    /// <p>The Amazon Resource Name (ARN) of the template.</p>
    pub fn template_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the template.</p>
    pub fn set_template_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the template.</p>
    pub fn get_template_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_arn
    }
    /// <p>The content of the template.</p><note>
    /// <p>Amazon SES supports only simple substitions when you send email using the <code>SendEmail</code> or <code>SendBulkEmail</code> operations and you provide the full template content in the request.</p>
    /// </note>
    pub fn template_content(mut self, input: crate::types::EmailTemplateContent) -> Self {
        self.template_content = ::std::option::Option::Some(input);
        self
    }
    /// <p>The content of the template.</p><note>
    /// <p>Amazon SES supports only simple substitions when you send email using the <code>SendEmail</code> or <code>SendBulkEmail</code> operations and you provide the full template content in the request.</p>
    /// </note>
    pub fn set_template_content(mut self, input: ::std::option::Option<crate::types::EmailTemplateContent>) -> Self {
        self.template_content = input;
        self
    }
    /// <p>The content of the template.</p><note>
    /// <p>Amazon SES supports only simple substitions when you send email using the <code>SendEmail</code> or <code>SendBulkEmail</code> operations and you provide the full template content in the request.</p>
    /// </note>
    pub fn get_template_content(&self) -> &::std::option::Option<crate::types::EmailTemplateContent> {
        &self.template_content
    }
    /// <p>An object that defines the values to use for message variables in the template. This object is a set of key-value pairs. Each key defines a message variable in the template. The corresponding value defines the value to use for that variable.</p>
    pub fn template_data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An object that defines the values to use for message variables in the template. This object is a set of key-value pairs. Each key defines a message variable in the template. The corresponding value defines the value to use for that variable.</p>
    pub fn set_template_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_data = input;
        self
    }
    /// <p>An object that defines the values to use for message variables in the template. This object is a set of key-value pairs. Each key defines a message variable in the template. The corresponding value defines the value to use for that variable.</p>
    pub fn get_template_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_data
    }
    /// Appends an item to `headers`.
    ///
    /// To override the contents of this collection use [`set_headers`](Self::set_headers).
    ///
    /// <p>The list of message headers that will be added to the email message.</p>
    pub fn headers(mut self, input: crate::types::MessageHeader) -> Self {
        let mut v = self.headers.unwrap_or_default();
        v.push(input);
        self.headers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of message headers that will be added to the email message.</p>
    pub fn set_headers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MessageHeader>>) -> Self {
        self.headers = input;
        self
    }
    /// <p>The list of message headers that will be added to the email message.</p>
    pub fn get_headers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MessageHeader>> {
        &self.headers
    }
    /// Appends an item to `attachments`.
    ///
    /// To override the contents of this collection use [`set_attachments`](Self::set_attachments).
    ///
    /// <p>The List of attachments to include in your email. All recipients will receive the same attachments.</p>
    pub fn attachments(mut self, input: crate::types::Attachment) -> Self {
        let mut v = self.attachments.unwrap_or_default();
        v.push(input);
        self.attachments = ::std::option::Option::Some(v);
        self
    }
    /// <p>The List of attachments to include in your email. All recipients will receive the same attachments.</p>
    pub fn set_attachments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Attachment>>) -> Self {
        self.attachments = input;
        self
    }
    /// <p>The List of attachments to include in your email. All recipients will receive the same attachments.</p>
    pub fn get_attachments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Attachment>> {
        &self.attachments
    }
    /// Consumes the builder and constructs a [`Template`](crate::types::Template).
    pub fn build(self) -> crate::types::Template {
        crate::types::Template {
            template_name: self.template_name,
            template_arn: self.template_arn,
            template_content: self.template_content,
            template_data: self.template_data,
            headers: self.headers,
            attachments: self.attachments,
        }
    }
}
