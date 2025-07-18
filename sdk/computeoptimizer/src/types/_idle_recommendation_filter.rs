// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a filter that returns a more specific list of idle resource recommendations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IdleRecommendationFilter {
    /// <p>The name of the filter.</p>
    /// <p>Specify <code>Finding</code> to return recommendations with a specific finding classification.</p>
    /// <p>You can filter your idle resource recommendations by <code>tag:key</code> and <code>tag-key</code> tags.</p>
    /// <p>A <code>tag:key</code> is a key and value combination of a tag assigned to your idle resource recommendations. Use the tag key in the filter name and the tag value as the filter value. For example, to find all idle resource service recommendations that have a tag with the key of <code>Owner</code> and the value of <code>TeamA</code>, specify <code>tag:Owner</code> for the filter name and <code>TeamA</code> for the filter value.</p>
    /// <p>A <code>tag-key</code> is the key of a tag assigned to your idle resource recommendations. Use this filter to find all of your idle resource recommendations that have a tag with a specific key. This doesn’t consider the tag value. For example, you can find your idle resource service recommendations with a tag key value of <code>Owner</code> or without any tag keys assigned.</p>
    pub name: ::std::option::Option<crate::types::IdleRecommendationFilterName>,
    /// <p>The value of the filter.</p>
    pub values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl IdleRecommendationFilter {
    /// <p>The name of the filter.</p>
    /// <p>Specify <code>Finding</code> to return recommendations with a specific finding classification.</p>
    /// <p>You can filter your idle resource recommendations by <code>tag:key</code> and <code>tag-key</code> tags.</p>
    /// <p>A <code>tag:key</code> is a key and value combination of a tag assigned to your idle resource recommendations. Use the tag key in the filter name and the tag value as the filter value. For example, to find all idle resource service recommendations that have a tag with the key of <code>Owner</code> and the value of <code>TeamA</code>, specify <code>tag:Owner</code> for the filter name and <code>TeamA</code> for the filter value.</p>
    /// <p>A <code>tag-key</code> is the key of a tag assigned to your idle resource recommendations. Use this filter to find all of your idle resource recommendations that have a tag with a specific key. This doesn’t consider the tag value. For example, you can find your idle resource service recommendations with a tag key value of <code>Owner</code> or without any tag keys assigned.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::IdleRecommendationFilterName> {
        self.name.as_ref()
    }
    /// <p>The value of the filter.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.values.is_none()`.
    pub fn values(&self) -> &[::std::string::String] {
        self.values.as_deref().unwrap_or_default()
    }
}
impl IdleRecommendationFilter {
    /// Creates a new builder-style object to manufacture [`IdleRecommendationFilter`](crate::types::IdleRecommendationFilter).
    pub fn builder() -> crate::types::builders::IdleRecommendationFilterBuilder {
        crate::types::builders::IdleRecommendationFilterBuilder::default()
    }
}

/// A builder for [`IdleRecommendationFilter`](crate::types::IdleRecommendationFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IdleRecommendationFilterBuilder {
    pub(crate) name: ::std::option::Option<crate::types::IdleRecommendationFilterName>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl IdleRecommendationFilterBuilder {
    /// <p>The name of the filter.</p>
    /// <p>Specify <code>Finding</code> to return recommendations with a specific finding classification.</p>
    /// <p>You can filter your idle resource recommendations by <code>tag:key</code> and <code>tag-key</code> tags.</p>
    /// <p>A <code>tag:key</code> is a key and value combination of a tag assigned to your idle resource recommendations. Use the tag key in the filter name and the tag value as the filter value. For example, to find all idle resource service recommendations that have a tag with the key of <code>Owner</code> and the value of <code>TeamA</code>, specify <code>tag:Owner</code> for the filter name and <code>TeamA</code> for the filter value.</p>
    /// <p>A <code>tag-key</code> is the key of a tag assigned to your idle resource recommendations. Use this filter to find all of your idle resource recommendations that have a tag with a specific key. This doesn’t consider the tag value. For example, you can find your idle resource service recommendations with a tag key value of <code>Owner</code> or without any tag keys assigned.</p>
    pub fn name(mut self, input: crate::types::IdleRecommendationFilterName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the filter.</p>
    /// <p>Specify <code>Finding</code> to return recommendations with a specific finding classification.</p>
    /// <p>You can filter your idle resource recommendations by <code>tag:key</code> and <code>tag-key</code> tags.</p>
    /// <p>A <code>tag:key</code> is a key and value combination of a tag assigned to your idle resource recommendations. Use the tag key in the filter name and the tag value as the filter value. For example, to find all idle resource service recommendations that have a tag with the key of <code>Owner</code> and the value of <code>TeamA</code>, specify <code>tag:Owner</code> for the filter name and <code>TeamA</code> for the filter value.</p>
    /// <p>A <code>tag-key</code> is the key of a tag assigned to your idle resource recommendations. Use this filter to find all of your idle resource recommendations that have a tag with a specific key. This doesn’t consider the tag value. For example, you can find your idle resource service recommendations with a tag key value of <code>Owner</code> or without any tag keys assigned.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::IdleRecommendationFilterName>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the filter.</p>
    /// <p>Specify <code>Finding</code> to return recommendations with a specific finding classification.</p>
    /// <p>You can filter your idle resource recommendations by <code>tag:key</code> and <code>tag-key</code> tags.</p>
    /// <p>A <code>tag:key</code> is a key and value combination of a tag assigned to your idle resource recommendations. Use the tag key in the filter name and the tag value as the filter value. For example, to find all idle resource service recommendations that have a tag with the key of <code>Owner</code> and the value of <code>TeamA</code>, specify <code>tag:Owner</code> for the filter name and <code>TeamA</code> for the filter value.</p>
    /// <p>A <code>tag-key</code> is the key of a tag assigned to your idle resource recommendations. Use this filter to find all of your idle resource recommendations that have a tag with a specific key. This doesn’t consider the tag value. For example, you can find your idle resource service recommendations with a tag key value of <code>Owner</code> or without any tag keys assigned.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::IdleRecommendationFilterName> {
        &self.name
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>The value of the filter.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The value of the filter.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>The value of the filter.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`IdleRecommendationFilter`](crate::types::IdleRecommendationFilter).
    pub fn build(self) -> crate::types::IdleRecommendationFilter {
        crate::types::IdleRecommendationFilter {
            name: self.name,
            values: self.values,
        }
    }
}
