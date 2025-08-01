// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAnycastIpListsInput {
    /// <p>Use this field when paginating results to indicate where to begin in your list. The response includes items in the list that occur after the marker. To get the next page of the list, set this field's value to the value of <code>NextMarker</code> from the current page's response.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of Anycast static IP lists that you want returned in the response.</p>
    pub max_items: ::std::option::Option<i32>,
}
impl ListAnycastIpListsInput {
    /// <p>Use this field when paginating results to indicate where to begin in your list. The response includes items in the list that occur after the marker. To get the next page of the list, set this field's value to the value of <code>NextMarker</code> from the current page's response.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>The maximum number of Anycast static IP lists that you want returned in the response.</p>
    pub fn max_items(&self) -> ::std::option::Option<i32> {
        self.max_items
    }
}
impl ListAnycastIpListsInput {
    /// Creates a new builder-style object to manufacture [`ListAnycastIpListsInput`](crate::operation::list_anycast_ip_lists::ListAnycastIpListsInput).
    pub fn builder() -> crate::operation::list_anycast_ip_lists::builders::ListAnycastIpListsInputBuilder {
        crate::operation::list_anycast_ip_lists::builders::ListAnycastIpListsInputBuilder::default()
    }
}

/// A builder for [`ListAnycastIpListsInput`](crate::operation::list_anycast_ip_lists::ListAnycastIpListsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAnycastIpListsInputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) max_items: ::std::option::Option<i32>,
}
impl ListAnycastIpListsInputBuilder {
    /// <p>Use this field when paginating results to indicate where to begin in your list. The response includes items in the list that occur after the marker. To get the next page of the list, set this field's value to the value of <code>NextMarker</code> from the current page's response.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Use this field when paginating results to indicate where to begin in your list. The response includes items in the list that occur after the marker. To get the next page of the list, set this field's value to the value of <code>NextMarker</code> from the current page's response.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>Use this field when paginating results to indicate where to begin in your list. The response includes items in the list that occur after the marker. To get the next page of the list, set this field's value to the value of <code>NextMarker</code> from the current page's response.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>The maximum number of Anycast static IP lists that you want returned in the response.</p>
    pub fn max_items(mut self, input: i32) -> Self {
        self.max_items = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of Anycast static IP lists that you want returned in the response.</p>
    pub fn set_max_items(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_items = input;
        self
    }
    /// <p>The maximum number of Anycast static IP lists that you want returned in the response.</p>
    pub fn get_max_items(&self) -> &::std::option::Option<i32> {
        &self.max_items
    }
    /// Consumes the builder and constructs a [`ListAnycastIpListsInput`](crate::operation::list_anycast_ip_lists::ListAnycastIpListsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_anycast_ip_lists::ListAnycastIpListsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_anycast_ip_lists::ListAnycastIpListsInput {
            marker: self.marker,
            max_items: self.max_items,
        })
    }
}
