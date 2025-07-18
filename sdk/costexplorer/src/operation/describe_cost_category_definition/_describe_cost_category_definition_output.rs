// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCostCategoryDefinitionOutput {
    /// <p>The structure of Cost Categories. This includes detailed metadata and the set of rules for the <code>CostCategory</code> object.</p>
    pub cost_category: ::std::option::Option<crate::types::CostCategory>,
    _request_id: Option<String>,
}
impl DescribeCostCategoryDefinitionOutput {
    /// <p>The structure of Cost Categories. This includes detailed metadata and the set of rules for the <code>CostCategory</code> object.</p>
    pub fn cost_category(&self) -> ::std::option::Option<&crate::types::CostCategory> {
        self.cost_category.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeCostCategoryDefinitionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeCostCategoryDefinitionOutput {
    /// Creates a new builder-style object to manufacture [`DescribeCostCategoryDefinitionOutput`](crate::operation::describe_cost_category_definition::DescribeCostCategoryDefinitionOutput).
    pub fn builder() -> crate::operation::describe_cost_category_definition::builders::DescribeCostCategoryDefinitionOutputBuilder {
        crate::operation::describe_cost_category_definition::builders::DescribeCostCategoryDefinitionOutputBuilder::default()
    }
}

/// A builder for [`DescribeCostCategoryDefinitionOutput`](crate::operation::describe_cost_category_definition::DescribeCostCategoryDefinitionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCostCategoryDefinitionOutputBuilder {
    pub(crate) cost_category: ::std::option::Option<crate::types::CostCategory>,
    _request_id: Option<String>,
}
impl DescribeCostCategoryDefinitionOutputBuilder {
    /// <p>The structure of Cost Categories. This includes detailed metadata and the set of rules for the <code>CostCategory</code> object.</p>
    pub fn cost_category(mut self, input: crate::types::CostCategory) -> Self {
        self.cost_category = ::std::option::Option::Some(input);
        self
    }
    /// <p>The structure of Cost Categories. This includes detailed metadata and the set of rules for the <code>CostCategory</code> object.</p>
    pub fn set_cost_category(mut self, input: ::std::option::Option<crate::types::CostCategory>) -> Self {
        self.cost_category = input;
        self
    }
    /// <p>The structure of Cost Categories. This includes detailed metadata and the set of rules for the <code>CostCategory</code> object.</p>
    pub fn get_cost_category(&self) -> &::std::option::Option<crate::types::CostCategory> {
        &self.cost_category
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeCostCategoryDefinitionOutput`](crate::operation::describe_cost_category_definition::DescribeCostCategoryDefinitionOutput).
    pub fn build(self) -> crate::operation::describe_cost_category_definition::DescribeCostCategoryDefinitionOutput {
        crate::operation::describe_cost_category_definition::DescribeCostCategoryDefinitionOutput {
            cost_category: self.cost_category,
            _request_id: self._request_id,
        }
    }
}
