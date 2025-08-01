// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateEndpointWeightsAndCapacitiesOutput {
    /// <p>The Amazon Resource Name (ARN) of the updated endpoint.</p>
    pub endpoint_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateEndpointWeightsAndCapacitiesOutput {
    /// <p>The Amazon Resource Name (ARN) of the updated endpoint.</p>
    pub fn endpoint_arn(&self) -> ::std::option::Option<&str> {
        self.endpoint_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateEndpointWeightsAndCapacitiesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateEndpointWeightsAndCapacitiesOutput {
    /// Creates a new builder-style object to manufacture [`UpdateEndpointWeightsAndCapacitiesOutput`](crate::operation::update_endpoint_weights_and_capacities::UpdateEndpointWeightsAndCapacitiesOutput).
    pub fn builder() -> crate::operation::update_endpoint_weights_and_capacities::builders::UpdateEndpointWeightsAndCapacitiesOutputBuilder {
        crate::operation::update_endpoint_weights_and_capacities::builders::UpdateEndpointWeightsAndCapacitiesOutputBuilder::default()
    }
}

/// A builder for [`UpdateEndpointWeightsAndCapacitiesOutput`](crate::operation::update_endpoint_weights_and_capacities::UpdateEndpointWeightsAndCapacitiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateEndpointWeightsAndCapacitiesOutputBuilder {
    pub(crate) endpoint_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateEndpointWeightsAndCapacitiesOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the updated endpoint.</p>
    /// This field is required.
    pub fn endpoint_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the updated endpoint.</p>
    pub fn set_endpoint_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the updated endpoint.</p>
    pub fn get_endpoint_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateEndpointWeightsAndCapacitiesOutput`](crate::operation::update_endpoint_weights_and_capacities::UpdateEndpointWeightsAndCapacitiesOutput).
    pub fn build(self) -> crate::operation::update_endpoint_weights_and_capacities::UpdateEndpointWeightsAndCapacitiesOutput {
        crate::operation::update_endpoint_weights_and_capacities::UpdateEndpointWeightsAndCapacitiesOutput {
            endpoint_arn: self.endpoint_arn,
            _request_id: self._request_id,
        }
    }
}
