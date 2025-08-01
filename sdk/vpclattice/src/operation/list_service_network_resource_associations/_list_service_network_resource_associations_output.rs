// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListServiceNetworkResourceAssociationsOutput {
    /// <p>Information about the associations.</p>
    pub items: ::std::vec::Vec<crate::types::ServiceNetworkResourceAssociationSummary>,
    /// <p>If there are additional results, a pagination token for the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListServiceNetworkResourceAssociationsOutput {
    /// <p>Information about the associations.</p>
    pub fn items(&self) -> &[crate::types::ServiceNetworkResourceAssociationSummary] {
        use std::ops::Deref;
        self.items.deref()
    }
    /// <p>If there are additional results, a pagination token for the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListServiceNetworkResourceAssociationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListServiceNetworkResourceAssociationsOutput {
    /// Creates a new builder-style object to manufacture [`ListServiceNetworkResourceAssociationsOutput`](crate::operation::list_service_network_resource_associations::ListServiceNetworkResourceAssociationsOutput).
    pub fn builder() -> crate::operation::list_service_network_resource_associations::builders::ListServiceNetworkResourceAssociationsOutputBuilder {
        crate::operation::list_service_network_resource_associations::builders::ListServiceNetworkResourceAssociationsOutputBuilder::default()
    }
}

/// A builder for [`ListServiceNetworkResourceAssociationsOutput`](crate::operation::list_service_network_resource_associations::ListServiceNetworkResourceAssociationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListServiceNetworkResourceAssociationsOutputBuilder {
    pub(crate) items: ::std::option::Option<::std::vec::Vec<crate::types::ServiceNetworkResourceAssociationSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListServiceNetworkResourceAssociationsOutputBuilder {
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>Information about the associations.</p>
    pub fn items(mut self, input: crate::types::ServiceNetworkResourceAssociationSummary) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input);
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the associations.</p>
    pub fn set_items(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ServiceNetworkResourceAssociationSummary>>) -> Self {
        self.items = input;
        self
    }
    /// <p>Information about the associations.</p>
    pub fn get_items(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ServiceNetworkResourceAssociationSummary>> {
        &self.items
    }
    /// <p>If there are additional results, a pagination token for the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are additional results, a pagination token for the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If there are additional results, a pagination token for the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListServiceNetworkResourceAssociationsOutput`](crate::operation::list_service_network_resource_associations::ListServiceNetworkResourceAssociationsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`items`](crate::operation::list_service_network_resource_associations::builders::ListServiceNetworkResourceAssociationsOutputBuilder::items)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_service_network_resource_associations::ListServiceNetworkResourceAssociationsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_service_network_resource_associations::ListServiceNetworkResourceAssociationsOutput {
                items: self.items.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "items",
                        "items was not specified but it is required when building ListServiceNetworkResourceAssociationsOutput",
                    )
                })?,
                next_token: self.next_token,
                _request_id: self._request_id,
            },
        )
    }
}
