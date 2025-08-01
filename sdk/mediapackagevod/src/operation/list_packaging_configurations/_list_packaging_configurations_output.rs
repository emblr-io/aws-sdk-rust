// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPackagingConfigurationsOutput {
    /// A token that can be used to resume pagination from the end of the collection.
    pub next_token: ::std::option::Option<::std::string::String>,
    /// A list of MediaPackage VOD PackagingConfiguration resources.
    pub packaging_configurations: ::std::option::Option<::std::vec::Vec<crate::types::PackagingConfiguration>>,
    _request_id: Option<String>,
}
impl ListPackagingConfigurationsOutput {
    /// A token that can be used to resume pagination from the end of the collection.
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// A list of MediaPackage VOD PackagingConfiguration resources.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.packaging_configurations.is_none()`.
    pub fn packaging_configurations(&self) -> &[crate::types::PackagingConfiguration] {
        self.packaging_configurations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListPackagingConfigurationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPackagingConfigurationsOutput {
    /// Creates a new builder-style object to manufacture [`ListPackagingConfigurationsOutput`](crate::operation::list_packaging_configurations::ListPackagingConfigurationsOutput).
    pub fn builder() -> crate::operation::list_packaging_configurations::builders::ListPackagingConfigurationsOutputBuilder {
        crate::operation::list_packaging_configurations::builders::ListPackagingConfigurationsOutputBuilder::default()
    }
}

/// A builder for [`ListPackagingConfigurationsOutput`](crate::operation::list_packaging_configurations::ListPackagingConfigurationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPackagingConfigurationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) packaging_configurations: ::std::option::Option<::std::vec::Vec<crate::types::PackagingConfiguration>>,
    _request_id: Option<String>,
}
impl ListPackagingConfigurationsOutputBuilder {
    /// A token that can be used to resume pagination from the end of the collection.
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// A token that can be used to resume pagination from the end of the collection.
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// A token that can be used to resume pagination from the end of the collection.
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `packaging_configurations`.
    ///
    /// To override the contents of this collection use [`set_packaging_configurations`](Self::set_packaging_configurations).
    ///
    /// A list of MediaPackage VOD PackagingConfiguration resources.
    pub fn packaging_configurations(mut self, input: crate::types::PackagingConfiguration) -> Self {
        let mut v = self.packaging_configurations.unwrap_or_default();
        v.push(input);
        self.packaging_configurations = ::std::option::Option::Some(v);
        self
    }
    /// A list of MediaPackage VOD PackagingConfiguration resources.
    pub fn set_packaging_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PackagingConfiguration>>) -> Self {
        self.packaging_configurations = input;
        self
    }
    /// A list of MediaPackage VOD PackagingConfiguration resources.
    pub fn get_packaging_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PackagingConfiguration>> {
        &self.packaging_configurations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListPackagingConfigurationsOutput`](crate::operation::list_packaging_configurations::ListPackagingConfigurationsOutput).
    pub fn build(self) -> crate::operation::list_packaging_configurations::ListPackagingConfigurationsOutput {
        crate::operation::list_packaging_configurations::ListPackagingConfigurationsOutput {
            next_token: self.next_token,
            packaging_configurations: self.packaging_configurations,
            _request_id: self._request_id,
        }
    }
}
