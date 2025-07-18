// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details regarding various fraud risk analyses performed against the current session state and streamed audio of the speaker.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FraudRiskDetails {
    /// <p>The details resulting from 'Known Fraudster Risk' analysis of the speaker.</p>
    pub known_fraudster_risk: ::std::option::Option<crate::types::KnownFraudsterRisk>,
    /// <p>The details resulting from 'Voice Spoofing Risk' analysis of the speaker.</p>
    pub voice_spoofing_risk: ::std::option::Option<crate::types::VoiceSpoofingRisk>,
}
impl FraudRiskDetails {
    /// <p>The details resulting from 'Known Fraudster Risk' analysis of the speaker.</p>
    pub fn known_fraudster_risk(&self) -> ::std::option::Option<&crate::types::KnownFraudsterRisk> {
        self.known_fraudster_risk.as_ref()
    }
    /// <p>The details resulting from 'Voice Spoofing Risk' analysis of the speaker.</p>
    pub fn voice_spoofing_risk(&self) -> ::std::option::Option<&crate::types::VoiceSpoofingRisk> {
        self.voice_spoofing_risk.as_ref()
    }
}
impl FraudRiskDetails {
    /// Creates a new builder-style object to manufacture [`FraudRiskDetails`](crate::types::FraudRiskDetails).
    pub fn builder() -> crate::types::builders::FraudRiskDetailsBuilder {
        crate::types::builders::FraudRiskDetailsBuilder::default()
    }
}

/// A builder for [`FraudRiskDetails`](crate::types::FraudRiskDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FraudRiskDetailsBuilder {
    pub(crate) known_fraudster_risk: ::std::option::Option<crate::types::KnownFraudsterRisk>,
    pub(crate) voice_spoofing_risk: ::std::option::Option<crate::types::VoiceSpoofingRisk>,
}
impl FraudRiskDetailsBuilder {
    /// <p>The details resulting from 'Known Fraudster Risk' analysis of the speaker.</p>
    /// This field is required.
    pub fn known_fraudster_risk(mut self, input: crate::types::KnownFraudsterRisk) -> Self {
        self.known_fraudster_risk = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details resulting from 'Known Fraudster Risk' analysis of the speaker.</p>
    pub fn set_known_fraudster_risk(mut self, input: ::std::option::Option<crate::types::KnownFraudsterRisk>) -> Self {
        self.known_fraudster_risk = input;
        self
    }
    /// <p>The details resulting from 'Known Fraudster Risk' analysis of the speaker.</p>
    pub fn get_known_fraudster_risk(&self) -> &::std::option::Option<crate::types::KnownFraudsterRisk> {
        &self.known_fraudster_risk
    }
    /// <p>The details resulting from 'Voice Spoofing Risk' analysis of the speaker.</p>
    /// This field is required.
    pub fn voice_spoofing_risk(mut self, input: crate::types::VoiceSpoofingRisk) -> Self {
        self.voice_spoofing_risk = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details resulting from 'Voice Spoofing Risk' analysis of the speaker.</p>
    pub fn set_voice_spoofing_risk(mut self, input: ::std::option::Option<crate::types::VoiceSpoofingRisk>) -> Self {
        self.voice_spoofing_risk = input;
        self
    }
    /// <p>The details resulting from 'Voice Spoofing Risk' analysis of the speaker.</p>
    pub fn get_voice_spoofing_risk(&self) -> &::std::option::Option<crate::types::VoiceSpoofingRisk> {
        &self.voice_spoofing_risk
    }
    /// Consumes the builder and constructs a [`FraudRiskDetails`](crate::types::FraudRiskDetails).
    pub fn build(self) -> crate::types::FraudRiskDetails {
        crate::types::FraudRiskDetails {
            known_fraudster_risk: self.known_fraudster_risk,
            voice_spoofing_risk: self.voice_spoofing_risk,
        }
    }
}
