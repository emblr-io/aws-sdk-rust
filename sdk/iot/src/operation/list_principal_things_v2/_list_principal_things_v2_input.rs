// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPrincipalThingsV2Input {
    /// <p>To retrieve the next set of results, the <code>nextToken</code> value from a previous response; otherwise <b>null</b> to receive the first set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in this operation.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The principal. A principal can be an X.509 certificate or an Amazon Cognito ID.</p>
    pub principal: ::std::option::Option<::std::string::String>,
    /// <p>The type of the relation you want to filter in the response. If no value is provided in this field, the response will list all things, including both the <code>EXCLUSIVE_THING</code> and <code>NON_EXCLUSIVE_THING</code> attachment types.</p>
    /// <ul>
    /// <li>
    /// <p><code>EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing, exclusively. The thing will be the only thing that’s attached to the principal.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p><code>NON_EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing. Multiple things can be attached to the principal.</p></li>
    /// </ul>
    pub thing_principal_type: ::std::option::Option<crate::types::ThingPrincipalType>,
}
impl ListPrincipalThingsV2Input {
    /// <p>To retrieve the next set of results, the <code>nextToken</code> value from a previous response; otherwise <b>null</b> to receive the first set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return in this operation.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The principal. A principal can be an X.509 certificate or an Amazon Cognito ID.</p>
    pub fn principal(&self) -> ::std::option::Option<&str> {
        self.principal.as_deref()
    }
    /// <p>The type of the relation you want to filter in the response. If no value is provided in this field, the response will list all things, including both the <code>EXCLUSIVE_THING</code> and <code>NON_EXCLUSIVE_THING</code> attachment types.</p>
    /// <ul>
    /// <li>
    /// <p><code>EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing, exclusively. The thing will be the only thing that’s attached to the principal.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p><code>NON_EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing. Multiple things can be attached to the principal.</p></li>
    /// </ul>
    pub fn thing_principal_type(&self) -> ::std::option::Option<&crate::types::ThingPrincipalType> {
        self.thing_principal_type.as_ref()
    }
}
impl ListPrincipalThingsV2Input {
    /// Creates a new builder-style object to manufacture [`ListPrincipalThingsV2Input`](crate::operation::list_principal_things_v2::ListPrincipalThingsV2Input).
    pub fn builder() -> crate::operation::list_principal_things_v2::builders::ListPrincipalThingsV2InputBuilder {
        crate::operation::list_principal_things_v2::builders::ListPrincipalThingsV2InputBuilder::default()
    }
}

/// A builder for [`ListPrincipalThingsV2Input`](crate::operation::list_principal_things_v2::ListPrincipalThingsV2Input).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPrincipalThingsV2InputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) principal: ::std::option::Option<::std::string::String>,
    pub(crate) thing_principal_type: ::std::option::Option<crate::types::ThingPrincipalType>,
}
impl ListPrincipalThingsV2InputBuilder {
    /// <p>To retrieve the next set of results, the <code>nextToken</code> value from a previous response; otherwise <b>null</b> to receive the first set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>To retrieve the next set of results, the <code>nextToken</code> value from a previous response; otherwise <b>null</b> to receive the first set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>To retrieve the next set of results, the <code>nextToken</code> value from a previous response; otherwise <b>null</b> to receive the first set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return in this operation.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in this operation.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in this operation.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The principal. A principal can be an X.509 certificate or an Amazon Cognito ID.</p>
    /// This field is required.
    pub fn principal(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The principal. A principal can be an X.509 certificate or an Amazon Cognito ID.</p>
    pub fn set_principal(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal = input;
        self
    }
    /// <p>The principal. A principal can be an X.509 certificate or an Amazon Cognito ID.</p>
    pub fn get_principal(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal
    }
    /// <p>The type of the relation you want to filter in the response. If no value is provided in this field, the response will list all things, including both the <code>EXCLUSIVE_THING</code> and <code>NON_EXCLUSIVE_THING</code> attachment types.</p>
    /// <ul>
    /// <li>
    /// <p><code>EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing, exclusively. The thing will be the only thing that’s attached to the principal.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p><code>NON_EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing. Multiple things can be attached to the principal.</p></li>
    /// </ul>
    pub fn thing_principal_type(mut self, input: crate::types::ThingPrincipalType) -> Self {
        self.thing_principal_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the relation you want to filter in the response. If no value is provided in this field, the response will list all things, including both the <code>EXCLUSIVE_THING</code> and <code>NON_EXCLUSIVE_THING</code> attachment types.</p>
    /// <ul>
    /// <li>
    /// <p><code>EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing, exclusively. The thing will be the only thing that’s attached to the principal.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p><code>NON_EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing. Multiple things can be attached to the principal.</p></li>
    /// </ul>
    pub fn set_thing_principal_type(mut self, input: ::std::option::Option<crate::types::ThingPrincipalType>) -> Self {
        self.thing_principal_type = input;
        self
    }
    /// <p>The type of the relation you want to filter in the response. If no value is provided in this field, the response will list all things, including both the <code>EXCLUSIVE_THING</code> and <code>NON_EXCLUSIVE_THING</code> attachment types.</p>
    /// <ul>
    /// <li>
    /// <p><code>EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing, exclusively. The thing will be the only thing that’s attached to the principal.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p><code>NON_EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing. Multiple things can be attached to the principal.</p></li>
    /// </ul>
    pub fn get_thing_principal_type(&self) -> &::std::option::Option<crate::types::ThingPrincipalType> {
        &self.thing_principal_type
    }
    /// Consumes the builder and constructs a [`ListPrincipalThingsV2Input`](crate::operation::list_principal_things_v2::ListPrincipalThingsV2Input).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_principal_things_v2::ListPrincipalThingsV2Input, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_principal_things_v2::ListPrincipalThingsV2Input {
            next_token: self.next_token,
            max_results: self.max_results,
            principal: self.principal,
            thing_principal_type: self.thing_principal_type,
        })
    }
}
