// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateRouteTableOutput {
    /// <p>The route table association ID. This ID is required for disassociating the route table.</p>
    pub association_id: ::std::option::Option<::std::string::String>,
    /// <p>The state of the association.</p>
    pub association_state: ::std::option::Option<crate::types::RouteTableAssociationState>,
    _request_id: Option<String>,
}
impl AssociateRouteTableOutput {
    /// <p>The route table association ID. This ID is required for disassociating the route table.</p>
    pub fn association_id(&self) -> ::std::option::Option<&str> {
        self.association_id.as_deref()
    }
    /// <p>The state of the association.</p>
    pub fn association_state(&self) -> ::std::option::Option<&crate::types::RouteTableAssociationState> {
        self.association_state.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for AssociateRouteTableOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateRouteTableOutput {
    /// Creates a new builder-style object to manufacture [`AssociateRouteTableOutput`](crate::operation::associate_route_table::AssociateRouteTableOutput).
    pub fn builder() -> crate::operation::associate_route_table::builders::AssociateRouteTableOutputBuilder {
        crate::operation::associate_route_table::builders::AssociateRouteTableOutputBuilder::default()
    }
}

/// A builder for [`AssociateRouteTableOutput`](crate::operation::associate_route_table::AssociateRouteTableOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateRouteTableOutputBuilder {
    pub(crate) association_id: ::std::option::Option<::std::string::String>,
    pub(crate) association_state: ::std::option::Option<crate::types::RouteTableAssociationState>,
    _request_id: Option<String>,
}
impl AssociateRouteTableOutputBuilder {
    /// <p>The route table association ID. This ID is required for disassociating the route table.</p>
    pub fn association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The route table association ID. This ID is required for disassociating the route table.</p>
    pub fn set_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.association_id = input;
        self
    }
    /// <p>The route table association ID. This ID is required for disassociating the route table.</p>
    pub fn get_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.association_id
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
    /// Consumes the builder and constructs a [`AssociateRouteTableOutput`](crate::operation::associate_route_table::AssociateRouteTableOutput).
    pub fn build(self) -> crate::operation::associate_route_table::AssociateRouteTableOutput {
        crate::operation::associate_route_table::AssociateRouteTableOutput {
            association_id: self.association_id,
            association_state: self.association_state,
            _request_id: self._request_id,
        }
    }
}
