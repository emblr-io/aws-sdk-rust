// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Filters to be applied to search results.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContactFlowSearchFilter {
    /// <p>An object that can be used to specify Tag conditions inside the <code>SearchFilter</code>. This accepts an <code>OR</code> of <code>AND</code> (List of List) input where:</p>
    /// <ul>
    /// <li>
    /// <p>Top level list specifies conditions that need to be applied with <code>OR</code> operator</p></li>
    /// <li>
    /// <p>Inner list specifies conditions that need to be applied with <code>AND</code> operator.</p></li>
    /// </ul>
    pub tag_filter: ::std::option::Option<crate::types::ControlPlaneTagFilter>,
}
impl ContactFlowSearchFilter {
    /// <p>An object that can be used to specify Tag conditions inside the <code>SearchFilter</code>. This accepts an <code>OR</code> of <code>AND</code> (List of List) input where:</p>
    /// <ul>
    /// <li>
    /// <p>Top level list specifies conditions that need to be applied with <code>OR</code> operator</p></li>
    /// <li>
    /// <p>Inner list specifies conditions that need to be applied with <code>AND</code> operator.</p></li>
    /// </ul>
    pub fn tag_filter(&self) -> ::std::option::Option<&crate::types::ControlPlaneTagFilter> {
        self.tag_filter.as_ref()
    }
}
impl ContactFlowSearchFilter {
    /// Creates a new builder-style object to manufacture [`ContactFlowSearchFilter`](crate::types::ContactFlowSearchFilter).
    pub fn builder() -> crate::types::builders::ContactFlowSearchFilterBuilder {
        crate::types::builders::ContactFlowSearchFilterBuilder::default()
    }
}

/// A builder for [`ContactFlowSearchFilter`](crate::types::ContactFlowSearchFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContactFlowSearchFilterBuilder {
    pub(crate) tag_filter: ::std::option::Option<crate::types::ControlPlaneTagFilter>,
}
impl ContactFlowSearchFilterBuilder {
    /// <p>An object that can be used to specify Tag conditions inside the <code>SearchFilter</code>. This accepts an <code>OR</code> of <code>AND</code> (List of List) input where:</p>
    /// <ul>
    /// <li>
    /// <p>Top level list specifies conditions that need to be applied with <code>OR</code> operator</p></li>
    /// <li>
    /// <p>Inner list specifies conditions that need to be applied with <code>AND</code> operator.</p></li>
    /// </ul>
    pub fn tag_filter(mut self, input: crate::types::ControlPlaneTagFilter) -> Self {
        self.tag_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that can be used to specify Tag conditions inside the <code>SearchFilter</code>. This accepts an <code>OR</code> of <code>AND</code> (List of List) input where:</p>
    /// <ul>
    /// <li>
    /// <p>Top level list specifies conditions that need to be applied with <code>OR</code> operator</p></li>
    /// <li>
    /// <p>Inner list specifies conditions that need to be applied with <code>AND</code> operator.</p></li>
    /// </ul>
    pub fn set_tag_filter(mut self, input: ::std::option::Option<crate::types::ControlPlaneTagFilter>) -> Self {
        self.tag_filter = input;
        self
    }
    /// <p>An object that can be used to specify Tag conditions inside the <code>SearchFilter</code>. This accepts an <code>OR</code> of <code>AND</code> (List of List) input where:</p>
    /// <ul>
    /// <li>
    /// <p>Top level list specifies conditions that need to be applied with <code>OR</code> operator</p></li>
    /// <li>
    /// <p>Inner list specifies conditions that need to be applied with <code>AND</code> operator.</p></li>
    /// </ul>
    pub fn get_tag_filter(&self) -> &::std::option::Option<crate::types::ControlPlaneTagFilter> {
        &self.tag_filter
    }
    /// Consumes the builder and constructs a [`ContactFlowSearchFilter`](crate::types::ContactFlowSearchFilter).
    pub fn build(self) -> crate::types::ContactFlowSearchFilter {
        crate::types::ContactFlowSearchFilter { tag_filter: self.tag_filter }
    }
}
