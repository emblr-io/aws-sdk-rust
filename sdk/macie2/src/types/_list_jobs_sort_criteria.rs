// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies criteria for sorting the results of a request for information about classification jobs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListJobsSortCriteria {
    /// <p>The property to sort the results by.</p>
    pub attribute_name: ::std::option::Option<crate::types::ListJobsSortAttributeName>,
    /// <p>The sort order to apply to the results, based on the value for the property specified by the attributeName property. Valid values are: ASC, sort the results in ascending order; and, DESC, sort the results in descending order.</p>
    pub order_by: ::std::option::Option<crate::types::OrderBy>,
}
impl ListJobsSortCriteria {
    /// <p>The property to sort the results by.</p>
    pub fn attribute_name(&self) -> ::std::option::Option<&crate::types::ListJobsSortAttributeName> {
        self.attribute_name.as_ref()
    }
    /// <p>The sort order to apply to the results, based on the value for the property specified by the attributeName property. Valid values are: ASC, sort the results in ascending order; and, DESC, sort the results in descending order.</p>
    pub fn order_by(&self) -> ::std::option::Option<&crate::types::OrderBy> {
        self.order_by.as_ref()
    }
}
impl ListJobsSortCriteria {
    /// Creates a new builder-style object to manufacture [`ListJobsSortCriteria`](crate::types::ListJobsSortCriteria).
    pub fn builder() -> crate::types::builders::ListJobsSortCriteriaBuilder {
        crate::types::builders::ListJobsSortCriteriaBuilder::default()
    }
}

/// A builder for [`ListJobsSortCriteria`](crate::types::ListJobsSortCriteria).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListJobsSortCriteriaBuilder {
    pub(crate) attribute_name: ::std::option::Option<crate::types::ListJobsSortAttributeName>,
    pub(crate) order_by: ::std::option::Option<crate::types::OrderBy>,
}
impl ListJobsSortCriteriaBuilder {
    /// <p>The property to sort the results by.</p>
    pub fn attribute_name(mut self, input: crate::types::ListJobsSortAttributeName) -> Self {
        self.attribute_name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The property to sort the results by.</p>
    pub fn set_attribute_name(mut self, input: ::std::option::Option<crate::types::ListJobsSortAttributeName>) -> Self {
        self.attribute_name = input;
        self
    }
    /// <p>The property to sort the results by.</p>
    pub fn get_attribute_name(&self) -> &::std::option::Option<crate::types::ListJobsSortAttributeName> {
        &self.attribute_name
    }
    /// <p>The sort order to apply to the results, based on the value for the property specified by the attributeName property. Valid values are: ASC, sort the results in ascending order; and, DESC, sort the results in descending order.</p>
    pub fn order_by(mut self, input: crate::types::OrderBy) -> Self {
        self.order_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sort order to apply to the results, based on the value for the property specified by the attributeName property. Valid values are: ASC, sort the results in ascending order; and, DESC, sort the results in descending order.</p>
    pub fn set_order_by(mut self, input: ::std::option::Option<crate::types::OrderBy>) -> Self {
        self.order_by = input;
        self
    }
    /// <p>The sort order to apply to the results, based on the value for the property specified by the attributeName property. Valid values are: ASC, sort the results in ascending order; and, DESC, sort the results in descending order.</p>
    pub fn get_order_by(&self) -> &::std::option::Option<crate::types::OrderBy> {
        &self.order_by
    }
    /// Consumes the builder and constructs a [`ListJobsSortCriteria`](crate::types::ListJobsSortCriteria).
    pub fn build(self) -> crate::types::ListJobsSortCriteria {
        crate::types::ListJobsSortCriteria {
            attribute_name: self.attribute_name,
            order_by: self.order_by,
        }
    }
}
