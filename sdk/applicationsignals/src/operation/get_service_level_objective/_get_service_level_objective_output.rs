// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetServiceLevelObjectiveOutput {
    /// <p>A structure containing the information about the SLO.</p>
    pub slo: ::std::option::Option<crate::types::ServiceLevelObjective>,
    _request_id: Option<String>,
}
impl GetServiceLevelObjectiveOutput {
    /// <p>A structure containing the information about the SLO.</p>
    pub fn slo(&self) -> ::std::option::Option<&crate::types::ServiceLevelObjective> {
        self.slo.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetServiceLevelObjectiveOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetServiceLevelObjectiveOutput {
    /// Creates a new builder-style object to manufacture [`GetServiceLevelObjectiveOutput`](crate::operation::get_service_level_objective::GetServiceLevelObjectiveOutput).
    pub fn builder() -> crate::operation::get_service_level_objective::builders::GetServiceLevelObjectiveOutputBuilder {
        crate::operation::get_service_level_objective::builders::GetServiceLevelObjectiveOutputBuilder::default()
    }
}

/// A builder for [`GetServiceLevelObjectiveOutput`](crate::operation::get_service_level_objective::GetServiceLevelObjectiveOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetServiceLevelObjectiveOutputBuilder {
    pub(crate) slo: ::std::option::Option<crate::types::ServiceLevelObjective>,
    _request_id: Option<String>,
}
impl GetServiceLevelObjectiveOutputBuilder {
    /// <p>A structure containing the information about the SLO.</p>
    /// This field is required.
    pub fn slo(mut self, input: crate::types::ServiceLevelObjective) -> Self {
        self.slo = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure containing the information about the SLO.</p>
    pub fn set_slo(mut self, input: ::std::option::Option<crate::types::ServiceLevelObjective>) -> Self {
        self.slo = input;
        self
    }
    /// <p>A structure containing the information about the SLO.</p>
    pub fn get_slo(&self) -> &::std::option::Option<crate::types::ServiceLevelObjective> {
        &self.slo
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetServiceLevelObjectiveOutput`](crate::operation::get_service_level_objective::GetServiceLevelObjectiveOutput).
    pub fn build(self) -> crate::operation::get_service_level_objective::GetServiceLevelObjectiveOutput {
        crate::operation::get_service_level_objective::GetServiceLevelObjectiveOutput {
            slo: self.slo,
            _request_id: self._request_id,
        }
    }
}
