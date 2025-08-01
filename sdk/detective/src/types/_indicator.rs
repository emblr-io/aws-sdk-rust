// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Detective investigations triages indicators of compromises such as a finding and surfaces only the most critical and suspicious issues, so you can focus on high-level investigations. An <code>Indicator</code> lets you determine if an Amazon Web Services resource is involved in unusual activity that could indicate malicious behavior and its impact.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Indicator {
    /// <p>The type of indicator.</p>
    pub indicator_type: ::std::option::Option<crate::types::IndicatorType>,
    /// <p>Details about the indicators of compromise that are used to determine if a resource is involved in a security incident. An indicator of compromise (IOC) is an artifact observed in or on a network, system, or environment that can (with a high level of confidence) identify malicious activity or a security incident.</p>
    pub indicator_detail: ::std::option::Option<crate::types::IndicatorDetail>,
}
impl Indicator {
    /// <p>The type of indicator.</p>
    pub fn indicator_type(&self) -> ::std::option::Option<&crate::types::IndicatorType> {
        self.indicator_type.as_ref()
    }
    /// <p>Details about the indicators of compromise that are used to determine if a resource is involved in a security incident. An indicator of compromise (IOC) is an artifact observed in or on a network, system, or environment that can (with a high level of confidence) identify malicious activity or a security incident.</p>
    pub fn indicator_detail(&self) -> ::std::option::Option<&crate::types::IndicatorDetail> {
        self.indicator_detail.as_ref()
    }
}
impl Indicator {
    /// Creates a new builder-style object to manufacture [`Indicator`](crate::types::Indicator).
    pub fn builder() -> crate::types::builders::IndicatorBuilder {
        crate::types::builders::IndicatorBuilder::default()
    }
}

/// A builder for [`Indicator`](crate::types::Indicator).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IndicatorBuilder {
    pub(crate) indicator_type: ::std::option::Option<crate::types::IndicatorType>,
    pub(crate) indicator_detail: ::std::option::Option<crate::types::IndicatorDetail>,
}
impl IndicatorBuilder {
    /// <p>The type of indicator.</p>
    pub fn indicator_type(mut self, input: crate::types::IndicatorType) -> Self {
        self.indicator_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of indicator.</p>
    pub fn set_indicator_type(mut self, input: ::std::option::Option<crate::types::IndicatorType>) -> Self {
        self.indicator_type = input;
        self
    }
    /// <p>The type of indicator.</p>
    pub fn get_indicator_type(&self) -> &::std::option::Option<crate::types::IndicatorType> {
        &self.indicator_type
    }
    /// <p>Details about the indicators of compromise that are used to determine if a resource is involved in a security incident. An indicator of compromise (IOC) is an artifact observed in or on a network, system, or environment that can (with a high level of confidence) identify malicious activity or a security incident.</p>
    pub fn indicator_detail(mut self, input: crate::types::IndicatorDetail) -> Self {
        self.indicator_detail = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the indicators of compromise that are used to determine if a resource is involved in a security incident. An indicator of compromise (IOC) is an artifact observed in or on a network, system, or environment that can (with a high level of confidence) identify malicious activity or a security incident.</p>
    pub fn set_indicator_detail(mut self, input: ::std::option::Option<crate::types::IndicatorDetail>) -> Self {
        self.indicator_detail = input;
        self
    }
    /// <p>Details about the indicators of compromise that are used to determine if a resource is involved in a security incident. An indicator of compromise (IOC) is an artifact observed in or on a network, system, or environment that can (with a high level of confidence) identify malicious activity or a security incident.</p>
    pub fn get_indicator_detail(&self) -> &::std::option::Option<crate::types::IndicatorDetail> {
        &self.indicator_detail
    }
    /// Consumes the builder and constructs a [`Indicator`](crate::types::Indicator).
    pub fn build(self) -> crate::types::Indicator {
        crate::types::Indicator {
            indicator_type: self.indicator_type,
            indicator_detail: self.indicator_detail,
        }
    }
}
