// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DeleteLabelsInput {
    /// <p>The ID of the resource.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>Amazon WorkDocs authentication token. Not required when using Amazon Web Services administrator credentials to access the API.</p>
    pub authentication_token: ::std::option::Option<::std::string::String>,
    /// <p>List of labels to delete from the resource.</p>
    pub labels: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Flag to request removal of all labels from the specified resource.</p>
    pub delete_all: ::std::option::Option<bool>,
}
impl DeleteLabelsInput {
    /// <p>The ID of the resource.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>Amazon WorkDocs authentication token. Not required when using Amazon Web Services administrator credentials to access the API.</p>
    pub fn authentication_token(&self) -> ::std::option::Option<&str> {
        self.authentication_token.as_deref()
    }
    /// <p>List of labels to delete from the resource.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.labels.is_none()`.
    pub fn labels(&self) -> &[::std::string::String] {
        self.labels.as_deref().unwrap_or_default()
    }
    /// <p>Flag to request removal of all labels from the specified resource.</p>
    pub fn delete_all(&self) -> ::std::option::Option<bool> {
        self.delete_all
    }
}
impl ::std::fmt::Debug for DeleteLabelsInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeleteLabelsInput");
        formatter.field("resource_id", &self.resource_id);
        formatter.field("authentication_token", &"*** Sensitive Data Redacted ***");
        formatter.field("labels", &self.labels);
        formatter.field("delete_all", &self.delete_all);
        formatter.finish()
    }
}
impl DeleteLabelsInput {
    /// Creates a new builder-style object to manufacture [`DeleteLabelsInput`](crate::operation::delete_labels::DeleteLabelsInput).
    pub fn builder() -> crate::operation::delete_labels::builders::DeleteLabelsInputBuilder {
        crate::operation::delete_labels::builders::DeleteLabelsInputBuilder::default()
    }
}

/// A builder for [`DeleteLabelsInput`](crate::operation::delete_labels::DeleteLabelsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DeleteLabelsInputBuilder {
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) authentication_token: ::std::option::Option<::std::string::String>,
    pub(crate) labels: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) delete_all: ::std::option::Option<bool>,
}
impl DeleteLabelsInputBuilder {
    /// <p>The ID of the resource.</p>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the resource.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The ID of the resource.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>Amazon WorkDocs authentication token. Not required when using Amazon Web Services administrator credentials to access the API.</p>
    pub fn authentication_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authentication_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon WorkDocs authentication token. Not required when using Amazon Web Services administrator credentials to access the API.</p>
    pub fn set_authentication_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authentication_token = input;
        self
    }
    /// <p>Amazon WorkDocs authentication token. Not required when using Amazon Web Services administrator credentials to access the API.</p>
    pub fn get_authentication_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.authentication_token
    }
    /// Appends an item to `labels`.
    ///
    /// To override the contents of this collection use [`set_labels`](Self::set_labels).
    ///
    /// <p>List of labels to delete from the resource.</p>
    pub fn labels(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.labels.unwrap_or_default();
        v.push(input.into());
        self.labels = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of labels to delete from the resource.</p>
    pub fn set_labels(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.labels = input;
        self
    }
    /// <p>List of labels to delete from the resource.</p>
    pub fn get_labels(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.labels
    }
    /// <p>Flag to request removal of all labels from the specified resource.</p>
    pub fn delete_all(mut self, input: bool) -> Self {
        self.delete_all = ::std::option::Option::Some(input);
        self
    }
    /// <p>Flag to request removal of all labels from the specified resource.</p>
    pub fn set_delete_all(mut self, input: ::std::option::Option<bool>) -> Self {
        self.delete_all = input;
        self
    }
    /// <p>Flag to request removal of all labels from the specified resource.</p>
    pub fn get_delete_all(&self) -> &::std::option::Option<bool> {
        &self.delete_all
    }
    /// Consumes the builder and constructs a [`DeleteLabelsInput`](crate::operation::delete_labels::DeleteLabelsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_labels::DeleteLabelsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_labels::DeleteLabelsInput {
            resource_id: self.resource_id,
            authentication_token: self.authentication_token,
            labels: self.labels,
            delete_all: self.delete_all,
        })
    }
}
impl ::std::fmt::Debug for DeleteLabelsInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeleteLabelsInputBuilder");
        formatter.field("resource_id", &self.resource_id);
        formatter.field("authentication_token", &"*** Sensitive Data Redacted ***");
        formatter.field("labels", &self.labels);
        formatter.field("delete_all", &self.delete_all);
        formatter.finish()
    }
}
