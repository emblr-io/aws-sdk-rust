// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReplaceRouteTableAssociationOutput {
    /// <p>The ID of the new association.</p>
    pub new_association_id: ::std::option::Option<::std::string::String>,
    /// <p>The state of the association.</p>
    pub association_state: ::std::option::Option<crate::types::RouteTableAssociationState>,
    _request_id: Option<String>,
}
impl ReplaceRouteTableAssociationOutput {
    /// <p>The ID of the new association.</p>
    pub fn new_association_id(&self) -> ::std::option::Option<&str> {
        self.new_association_id.as_deref()
    }
    /// <p>The state of the association.</p>
    pub fn association_state(&self) -> ::std::option::Option<&crate::types::RouteTableAssociationState> {
        self.association_state.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ReplaceRouteTableAssociationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ReplaceRouteTableAssociationOutput {
    /// Creates a new builder-style object to manufacture [`ReplaceRouteTableAssociationOutput`](crate::operation::replace_route_table_association::ReplaceRouteTableAssociationOutput).
    pub fn builder() -> crate::operation::replace_route_table_association::builders::ReplaceRouteTableAssociationOutputBuilder {
        crate::operation::replace_route_table_association::builders::ReplaceRouteTableAssociationOutputBuilder::default()
    }
}

/// A builder for [`ReplaceRouteTableAssociationOutput`](crate::operation::replace_route_table_association::ReplaceRouteTableAssociationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReplaceRouteTableAssociationOutputBuilder {
    pub(crate) new_association_id: ::std::option::Option<::std::string::String>,
    pub(crate) association_state: ::std::option::Option<crate::types::RouteTableAssociationState>,
    _request_id: Option<String>,
}
impl ReplaceRouteTableAssociationOutputBuilder {
    /// <p>The ID of the new association.</p>
    pub fn new_association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the new association.</p>
    pub fn set_new_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_association_id = input;
        self
    }
    /// <p>The ID of the new association.</p>
    pub fn get_new_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_association_id
    }
    /// <p>The state of the association.</p>
    pub fn association_state(mut self, input: crate::types::RouteTableAssociationState) -> Self {
        self.association_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the association.</p>
    pub fn set_association_state(mut self, input: ::std::option::Option<crate::types::RouteTableAssociationState>) -> Self {
        self.association_state = input;
        self
    }
    /// <p>The state of the association.</p>
    pub fn get_association_state(&self) -> &::std::option::Option<crate::types::RouteTableAssociationState> {
        &self.association_state
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ReplaceRouteTableAssociationOutput`](crate::operation::replace_route_table_association::ReplaceRouteTableAssociationOutput).
    pub fn build(self) -> crate::operation::replace_route_table_association::ReplaceRouteTableAssociationOutput {
        crate::operation::replace_route_table_association::ReplaceRouteTableAssociationOutput {
            new_association_id: self.new_association_id,
            association_state: self.association_state,
            _request_id: self._request_id,
        }
    }
}
