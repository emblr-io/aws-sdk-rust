// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `PluginType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let plugintype = unimplemented!();
/// match plugintype {
///     PluginType::Asana => { /* ... */ },
///     PluginType::AtlassianConfluence => { /* ... */ },
///     PluginType::Custom => { /* ... */ },
///     PluginType::GoogleCalendar => { /* ... */ },
///     PluginType::Jira => { /* ... */ },
///     PluginType::JiraCloud => { /* ... */ },
///     PluginType::MicrosoftExchange => { /* ... */ },
///     PluginType::MicrosoftTeams => { /* ... */ },
///     PluginType::PagerdutyAdvance => { /* ... */ },
///     PluginType::Quicksight => { /* ... */ },
///     PluginType::Salesforce => { /* ... */ },
///     PluginType::SalesforceCrm => { /* ... */ },
///     PluginType::ServicenowNowPlatform => { /* ... */ },
///     PluginType::ServiceNow => { /* ... */ },
///     PluginType::Smartsheet => { /* ... */ },
///     PluginType::Zendesk => { /* ... */ },
///     PluginType::ZendeskSuite => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `plugintype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `PluginType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `PluginType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `PluginType::NewFeature` is defined.
/// Specifically, when `plugintype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `PluginType::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum PluginType {
    #[allow(missing_docs)] // documentation missing in model
    Asana,
    #[allow(missing_docs)] // documentation missing in model
    AtlassianConfluence,
    #[allow(missing_docs)] // documentation missing in model
    Custom,
    #[allow(missing_docs)] // documentation missing in model
    GoogleCalendar,
    #[allow(missing_docs)] // documentation missing in model
    Jira,
    #[allow(missing_docs)] // documentation missing in model
    JiraCloud,
    #[allow(missing_docs)] // documentation missing in model
    MicrosoftExchange,
    #[allow(missing_docs)] // documentation missing in model
    MicrosoftTeams,
    #[allow(missing_docs)] // documentation missing in model
    PagerdutyAdvance,
    #[allow(missing_docs)] // documentation missing in model
    Quicksight,
    #[allow(missing_docs)] // documentation missing in model
    Salesforce,
    #[allow(missing_docs)] // documentation missing in model
    SalesforceCrm,
    #[allow(missing_docs)] // documentation missing in model
    ServicenowNowPlatform,
    #[allow(missing_docs)] // documentation missing in model
    ServiceNow,
    #[allow(missing_docs)] // documentation missing in model
    Smartsheet,
    #[allow(missing_docs)] // documentation missing in model
    Zendesk,
    #[allow(missing_docs)] // documentation missing in model
    ZendeskSuite,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for PluginType {
    fn from(s: &str) -> Self {
        match s {
            "ASANA" => PluginType::Asana,
            "ATLASSIAN_CONFLUENCE" => PluginType::AtlassianConfluence,
            "CUSTOM" => PluginType::Custom,
            "GOOGLE_CALENDAR" => PluginType::GoogleCalendar,
            "JIRA" => PluginType::Jira,
            "JIRA_CLOUD" => PluginType::JiraCloud,
            "MICROSOFT_EXCHANGE" => PluginType::MicrosoftExchange,
            "MICROSOFT_TEAMS" => PluginType::MicrosoftTeams,
            "PAGERDUTY_ADVANCE" => PluginType::PagerdutyAdvance,
            "QUICKSIGHT" => PluginType::Quicksight,
            "SALESFORCE" => PluginType::Salesforce,
            "SALESFORCE_CRM" => PluginType::SalesforceCrm,
            "SERVICENOW_NOW_PLATFORM" => PluginType::ServicenowNowPlatform,
            "SERVICE_NOW" => PluginType::ServiceNow,
            "SMARTSHEET" => PluginType::Smartsheet,
            "ZENDESK" => PluginType::Zendesk,
            "ZENDESK_SUITE" => PluginType::ZendeskSuite,
            other => PluginType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for PluginType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(PluginType::from(s))
    }
}
impl PluginType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            PluginType::Asana => "ASANA",
            PluginType::AtlassianConfluence => "ATLASSIAN_CONFLUENCE",
            PluginType::Custom => "CUSTOM",
            PluginType::GoogleCalendar => "GOOGLE_CALENDAR",
            PluginType::Jira => "JIRA",
            PluginType::JiraCloud => "JIRA_CLOUD",
            PluginType::MicrosoftExchange => "MICROSOFT_EXCHANGE",
            PluginType::MicrosoftTeams => "MICROSOFT_TEAMS",
            PluginType::PagerdutyAdvance => "PAGERDUTY_ADVANCE",
            PluginType::Quicksight => "QUICKSIGHT",
            PluginType::Salesforce => "SALESFORCE",
            PluginType::SalesforceCrm => "SALESFORCE_CRM",
            PluginType::ServicenowNowPlatform => "SERVICENOW_NOW_PLATFORM",
            PluginType::ServiceNow => "SERVICE_NOW",
            PluginType::Smartsheet => "SMARTSHEET",
            PluginType::Zendesk => "ZENDESK",
            PluginType::ZendeskSuite => "ZENDESK_SUITE",
            PluginType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "ASANA",
            "ATLASSIAN_CONFLUENCE",
            "CUSTOM",
            "GOOGLE_CALENDAR",
            "JIRA",
            "JIRA_CLOUD",
            "MICROSOFT_EXCHANGE",
            "MICROSOFT_TEAMS",
            "PAGERDUTY_ADVANCE",
            "QUICKSIGHT",
            "SALESFORCE",
            "SALESFORCE_CRM",
            "SERVICENOW_NOW_PLATFORM",
            "SERVICE_NOW",
            "SMARTSHEET",
            "ZENDESK",
            "ZENDESK_SUITE",
        ]
    }
}
impl ::std::convert::AsRef<str> for PluginType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl PluginType {
    /// Parses the enum value while disallowing unknown variants.
    ///
    /// Unknown variants will result in an error.
    pub fn try_parse(value: &str) -> ::std::result::Result<Self, crate::error::UnknownVariantError> {
        match Self::from(value) {
            #[allow(deprecated)]
            Self::Unknown(_) => ::std::result::Result::Err(crate::error::UnknownVariantError::new(value)),
            known => Ok(known),
        }
    }
}
impl ::std::fmt::Display for PluginType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            PluginType::Asana => write!(f, "ASANA"),
            PluginType::AtlassianConfluence => write!(f, "ATLASSIAN_CONFLUENCE"),
            PluginType::Custom => write!(f, "CUSTOM"),
            PluginType::GoogleCalendar => write!(f, "GOOGLE_CALENDAR"),
            PluginType::Jira => write!(f, "JIRA"),
            PluginType::JiraCloud => write!(f, "JIRA_CLOUD"),
            PluginType::MicrosoftExchange => write!(f, "MICROSOFT_EXCHANGE"),
            PluginType::MicrosoftTeams => write!(f, "MICROSOFT_TEAMS"),
            PluginType::PagerdutyAdvance => write!(f, "PAGERDUTY_ADVANCE"),
            PluginType::Quicksight => write!(f, "QUICKSIGHT"),
            PluginType::Salesforce => write!(f, "SALESFORCE"),
            PluginType::SalesforceCrm => write!(f, "SALESFORCE_CRM"),
            PluginType::ServicenowNowPlatform => write!(f, "SERVICENOW_NOW_PLATFORM"),
            PluginType::ServiceNow => write!(f, "SERVICE_NOW"),
            PluginType::Smartsheet => write!(f, "SMARTSHEET"),
            PluginType::Zendesk => write!(f, "ZENDESK"),
            PluginType::ZendeskSuite => write!(f, "ZENDESK_SUITE"),
            PluginType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
