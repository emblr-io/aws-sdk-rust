// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPricingPlanOutput {
    /// <p>The chosen pricing plan for the current billing cycle.</p>
    pub current_pricing_plan: ::std::option::Option<crate::types::PricingPlan>,
    /// <p>The pending pricing plan.</p>
    pub pending_pricing_plan: ::std::option::Option<crate::types::PricingPlan>,
    _request_id: Option<String>,
}
impl GetPricingPlanOutput {
    /// <p>The chosen pricing plan for the current billing cycle.</p>
    pub fn current_pricing_plan(&self) -> ::std::option::Option<&crate::types::PricingPlan> {
        self.current_pricing_plan.as_ref()
    }
    /// <p>The pending pricing plan.</p>
    pub fn pending_pricing_plan(&self) -> ::std::option::Option<&crate::types::PricingPlan> {
        self.pending_pricing_plan.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetPricingPlanOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetPricingPlanOutput {
    /// Creates a new builder-style object to manufacture [`GetPricingPlanOutput`](crate::operation::get_pricing_plan::GetPricingPlanOutput).
    pub fn builder() -> crate::operation::get_pricing_plan::builders::GetPricingPlanOutputBuilder {
        crate::operation::get_pricing_plan::builders::GetPricingPlanOutputBuilder::default()
    }
}

/// A builder for [`GetPricingPlanOutput`](crate::operation::get_pricing_plan::GetPricingPlanOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPricingPlanOutputBuilder {
    pub(crate) current_pricing_plan: ::std::option::Option<crate::types::PricingPlan>,
    pub(crate) pending_pricing_plan: ::std::option::Option<crate::types::PricingPlan>,
    _request_id: Option<String>,
}
impl GetPricingPlanOutputBuilder {
    /// <p>The chosen pricing plan for the current billing cycle.</p>
    /// This field is required.
    pub fn current_pricing_plan(mut self, input: crate::types::PricingPlan) -> Self {
        self.current_pricing_plan = ::std::option::Option::Some(input);
        self
    }
    /// <p>The chosen pricing plan for the current billing cycle.</p>
    pub fn set_current_pricing_plan(mut self, input: ::std::option::Option<crate::types::PricingPlan>) -> Self {
        self.current_pricing_plan = input;
        self
    }
    /// <p>The chosen pricing plan for the current billing cycle.</p>
    pub fn get_current_pricing_plan(&self) -> &::std::option::Option<crate::types::PricingPlan> {
        &self.current_pricing_plan
    }
    /// <p>The pending pricing plan.</p>
    pub fn pending_pricing_plan(mut self, input: crate::types::PricingPlan) -> Self {
        self.pending_pricing_plan = ::std::option::Option::Some(input);
        self
    }
    /// <p>The pending pricing plan.</p>
    pub fn set_pending_pricing_plan(mut self, input: ::std::option::Option<crate::types::PricingPlan>) -> Self {
        self.pending_pricing_plan = input;
        self
    }
    /// <p>The pending pricing plan.</p>
    pub fn get_pending_pricing_plan(&self) -> &::std::option::Option<crate::types::PricingPlan> {
        &self.pending_pricing_plan
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetPricingPlanOutput`](crate::operation::get_pricing_plan::GetPricingPlanOutput).
    pub fn build(self) -> crate::operation::get_pricing_plan::GetPricingPlanOutput {
        crate::operation::get_pricing_plan::GetPricingPlanOutput {
            current_pricing_plan: self.current_pricing_plan,
            pending_pricing_plan: self.pending_pricing_plan,
            _request_id: self._request_id,
        }
    }
}
