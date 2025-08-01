// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateLabelGroupInput {
    /// <p>Names a group of labels.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub label_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The acceptable fault codes (indicating the type of anomaly associated with the label) that can be used with this label group.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fault_codes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A unique identifier for the request to create a label group. If you do not set the client request token, Lookout for Equipment generates one.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Tags that provide metadata about the label group you are creating.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateLabelGroupInput {
    /// <p>Names a group of labels.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn label_group_name(&self) -> ::std::option::Option<&str> {
        self.label_group_name.as_deref()
    }
    /// <p>The acceptable fault codes (indicating the type of anomaly associated with the label) that can be used with this label group.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.fault_codes.is_none()`.
    pub fn fault_codes(&self) -> &[::std::string::String] {
        self.fault_codes.as_deref().unwrap_or_default()
    }
    /// <p>A unique identifier for the request to create a label group. If you do not set the client request token, Lookout for Equipment generates one.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Tags that provide metadata about the label group you are creating.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateLabelGroupInput {
    /// Creates a new builder-style object to manufacture [`CreateLabelGroupInput`](crate::operation::create_label_group::CreateLabelGroupInput).
    pub fn builder() -> crate::operation::create_label_group::builders::CreateLabelGroupInputBuilder {
        crate::operation::create_label_group::builders::CreateLabelGroupInputBuilder::default()
    }
}

/// A builder for [`CreateLabelGroupInput`](crate::operation::create_label_group::CreateLabelGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateLabelGroupInputBuilder {
    pub(crate) label_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) fault_codes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateLabelGroupInputBuilder {
    /// <p>Names a group of labels.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    /// This field is required.
    pub fn label_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.label_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Names a group of labels.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn set_label_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.label_group_name = input;
        self
    }
    /// <p>Names a group of labels.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn get_label_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.label_group_name
    }
    /// Appends an item to `fault_codes`.
    ///
    /// To override the contents of this collection use [`set_fault_codes`](Self::set_fault_codes).
    ///
    /// <p>The acceptable fault codes (indicating the type of anomaly associated with the label) that can be used with this label group.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn fault_codes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.fault_codes.unwrap_or_default();
        v.push(input.into());
        self.fault_codes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The acceptable fault codes (indicating the type of anomaly associated with the label) that can be used with this label group.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn set_fault_codes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.fault_codes = input;
        self
    }
    /// <p>The acceptable fault codes (indicating the type of anomaly associated with the label) that can be used with this label group.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn get_fault_codes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.fault_codes
    }
    /// <p>A unique identifier for the request to create a label group. If you do not set the client request token, Lookout for Equipment generates one.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the request to create a label group. If you do not set the client request token, Lookout for Equipment generates one.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique identifier for the request to create a label group. If you do not set the client request token, Lookout for Equipment generates one.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags that provide metadata about the label group you are creating.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Tags that provide metadata about the label group you are creating.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags that provide metadata about the label group you are creating.</p>
    /// <p>Data in this field will be retained for service usage. Follow best practices for the security of your data.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateLabelGroupInput`](crate::operation::create_label_group::CreateLabelGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_label_group::CreateLabelGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_label_group::CreateLabelGroupInput {
            label_group_name: self.label_group_name,
            fault_codes: self.fault_codes,
            client_token: self.client_token,
            tags: self.tags,
        })
    }
}
