// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The GetEntitlementsRequest contains results from the GetEntitlements operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEntitlementsOutput {
    /// <p>The set of entitlements found through the GetEntitlements operation. If the result contains an empty set of entitlements, NextToken might still be present and should be used.</p>
    pub entitlements: ::std::option::Option<::std::vec::Vec<crate::types::Entitlement>>,
    /// <p>For paginated results, use NextToken in subsequent calls to GetEntitlements. If the result contains an empty set of entitlements, NextToken might still be present and should be used.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetEntitlementsOutput {
    /// <p>The set of entitlements found through the GetEntitlements operation. If the result contains an empty set of entitlements, NextToken might still be present and should be used.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.entitlements.is_none()`.
    pub fn entitlements(&self) -> &[crate::types::Entitlement] {
        self.entitlements.as_deref().unwrap_or_default()
    }
    /// <p>For paginated results, use NextToken in subsequent calls to GetEntitlements. If the result contains an empty set of entitlements, NextToken might still be present and should be used.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetEntitlementsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetEntitlementsOutput {
    /// Creates a new builder-style object to manufacture [`GetEntitlementsOutput`](crate::operation::get_entitlements::GetEntitlementsOutput).
    pub fn builder() -> crate::operation::get_entitlements::builders::GetEntitlementsOutputBuilder {
        crate::operation::get_entitlements::builders::GetEntitlementsOutputBuilder::default()
    }
}

/// A builder for [`GetEntitlementsOutput`](crate::operation::get_entitlements::GetEntitlementsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEntitlementsOutputBuilder {
    pub(crate) entitlements: ::std::option::Option<::std::vec::Vec<crate::types::Entitlement>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetEntitlementsOutputBuilder {
    /// Appends an item to `entitlements`.
    ///
    /// To override the contents of this collection use [`set_entitlements`](Self::set_entitlements).
    ///
    /// <p>The set of entitlements found through the GetEntitlements operation. If the result contains an empty set of entitlements, NextToken might still be present and should be used.</p>
    pub fn entitlements(mut self, input: crate::types::Entitlement) -> Self {
        let mut v = self.entitlements.unwrap_or_default();
        v.push(input);
        self.entitlements = ::std::option::Option::Some(v);
        self
    }
    /// <p>The set of entitlements found through the GetEntitlements operation. If the result contains an empty set of entitlements, NextToken might still be present and should be used.</p>
    pub fn set_entitlements(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Entitlement>>) -> Self {
        self.entitlements = input;
        self
    }
    /// <p>The set of entitlements found through the GetEntitlements operation. If the result contains an empty set of entitlements, NextToken might still be present and should be used.</p>
    pub fn get_entitlements(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Entitlement>> {
        &self.entitlements
    }
    /// <p>For paginated results, use NextToken in subsequent calls to GetEntitlements. If the result contains an empty set of entitlements, NextToken might still be present and should be used.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For paginated results, use NextToken in subsequent calls to GetEntitlements. If the result contains an empty set of entitlements, NextToken might still be present and should be used.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>For paginated results, use NextToken in subsequent calls to GetEntitlements. If the result contains an empty set of entitlements, NextToken might still be present and should be used.</p>
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
    /// Consumes the builder and constructs a [`GetEntitlementsOutput`](crate::operation::get_entitlements::GetEntitlementsOutput).
    pub fn build(self) -> crate::operation::get_entitlements::GetEntitlementsOutput {
        crate::operation::get_entitlements::GetEntitlementsOutput {
            entitlements: self.entitlements,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
