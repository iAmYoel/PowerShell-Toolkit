$ListOfCompanys = @{}

    $ListOfCompanys["select"] = @{
    "Danir AB"                              = @{"OU" = "OU=Users,OU=Danir,OU=SigmaGroup,DC=Sigma,DC=Local";                                              "Domain" = "danir.com";                 "Database" = "DAB"};
    
    ## Nexer
    "Nexer AB"                              = @{"OU" = "OU=Users,OU=Sigma IT Consulting Sweden,OU=SigmaGroup,DC=Sigma,DC=Local";                                     "Domain" = "nexergroup.com";        "Database" = "SITCSWE"};
    #"Nexer Asset Management AS"             = @{"OU" = "OU=Users,OU=Sigma IT Management Norway,OU=SigmaGroup,DC=sigma,DC=local";                                     "Domain" = "nexergroup.com";        "Database" = ""};
    "Nexer Asset Management Oy"             = @{"OU" = "OU=Users,OU=Sigma IT Consulting Finland,OU=SigmaGroup,DC=sigma,DC=local";                                    "Domain" = "nexergroup.com";        "Database" = "SIGMAOY"};
    "Nexer Cybersecurity AB"                = @{"OU" = "OU=Users,OU=Sigma Cybersecurity,OU=SigmaGroup,DC=sigma,DC=local";                                            "Domain" = "nexergroup.com";        "Database" = "S408"};
    "Nexer Digital Ltd"                     = @{"OU" = "OU=Users,OU=Sigma IT Consulting UK,OU=SigmaGroup,DC=sigma,DC=local";                                         "Domain" = "nexergroup.com";        "Database" = ""};
    "Nexer Enterprise Applications AB"      = @{"OU" = "OU=Users,OU=Sigma Enterprise Applications,OU=SigmaGroup,DC=sigma,DC=local";                                  "Domain" = "nexergroup.com";        "Database" = "S406"};
    "Nexer Enterprise Applications Ltd"     = @{"OU" = "OU=Users,OU=Enterprise Applications Ltd,OU=Sigma Enterprise Applications,OU=SigmaGroup,DC=sigma,DC=local";   "Domain" = "nexergroup.com";        "Database" = ""};
    "Nexer Enterprise Applications Inc"     = @{"OU" = "OU=Users,OU=Enterprise Applications Inc,OU=Sigma Enterprise Applications,OU=SigmaGroup,DC=sigma,DC=local";   "Domain" = "nexergroup.com";        "Database" = ""};
    "Nexer Enterprise Applications Prv Ltd" = @{"OU" = "OU=Users,OU=Enterprise Applications India,OU=Sigma Enterprise Applications,OU=SigmaGroup,DC=sigma,DC=local"; "Domain" = "nexergroup.com";        "Database" = "S444"};
    "Nexer Infrastructure AB"               = @{"OU" = "OU=Users,OU=Sigma IT Tech,OU=Sigma Resources,OU=SigmaGroup,DC=sigma,DC=local";                               "Domain" = "nexergroup.com";        "Database" = "S904"};
    "Nexer Insight AB"                      = @{"OU" = "OU=Users,OU=Insight,OU=SigmaGroup,DC=sigma,DC=local";                                                        "Domain" = "nexergroup.com";        "Database" = "S407"};
    "Nexer Insight Inc"                     = @{"OU" = "OU=Users,OU=Sigma IT Consulting Inc,OU=SigmaGroup,DC=Sigma,DC=Local";                                        "Domain" = "nexergroup.com";        "Database" = ""};
    "Nexer Insight Ltd"                     = @{"OU" = "OU=Users,OU=Insight Ltd,OU=Insight,OU=SigmaGroup,DC=sigma,DC=local";                                         "Domain" = "nexergroup.com";        "Database" = ""};
    "Nexer Insight Sp. z o.o."              = @{"OU" = "OU=Users,OU=Insight Poland,OU=Insight,OU=SigmaGroup,DC=sigma,DC=local";                                      "Domain" = "nexergroup.com";        "Database" = "S446"};
    "Nexer IT Services AB"                  = @{"OU" = "OU=Users,OU=Sigma Serve,OU=SigmaGroup,DC=Sigma,DC=Local";                                                    "Domain" = "nexergroup.com";        "Database" = "S409"};
    "Nexer Prv Ltd"                         = @{"OU" = "OU=Users,OU=Sigma IT Consulting India,OU=SigmaGroup,DC=sigma,DC=local";                                      "Domain" = "nexergroup.com";        "Database" = "SITCIND"};
    "Nexer Recruit AB"                      = @{"OU" = "OU=Users,OU=Sigma Recruit,OU=Sigma Resources,OU=SigmaGroup,DC=sigma,DC=local";                               "Domain" = "nexergroup.com";        "Database" = "SCOMSWE"};
    #"Nexer Society AB?"                     = @{"OU" = "OU=Users,OU=Sigma Society,OU=Sigma Resources,OU=SigmaGroup,DC=sigma,DC=local";                               "Domain" = "nexergroup.com";        "Database" = ""};
    "Nexer A Society AB"                    = @{"OU" = "OU=Users,OU=Nexer A Society AB,OU=SigmaGroup,DC=sigma,DC=local";                                             "Domain" = "nexergroup.com";        "Database" = "S895"};
    "Nexer Sp. z o.o."                      = @{"OU" = "OU=Users,OU=Sigma IT Consulting Poland,OU=SigmaGroup,DC=sigma,DC=local";                                     "Domain" = "nexergroup.com";        "Database" = "SITCPOL"};
    "Nexer Tech Talent AB"                  = @{"OU" = "OU=Users,OU=Sigma Young Talent,OU=Sigma Resources,OU=SigmaGroup,DC=sigma,DC=local";                          "Domain" = "nexergroup.com";        "Database" = "SINOSWE"};


    ## Sigma (Old/Temp)
    "Sigma Cybersecurity AB"            = @{"OU" = "OU=Users,OU=Sigma Cybersecurity,OU=SigmaGroup,DC=sigma,DC=local";           "Domain" = "sigma.se";    "Database" = "S408"};
    "Sigma IT Polska Sp. z o.o."        = @{"OU" = "OU=Users,OU=Sigma IT Consulting Poland,OU=SigmaGroup,DC=sigma,DC=local";    "Domain" = "sigma.se";    "Database" = "SITCPOL"};


    ## Sigma
    "Sigma Civil AB"                    = @{"OU" = "OU=Users,OU=Sigma Civil,OU=SigmaGroup,DC=Sigma,DC=Local";                                                  "Domain" = "sigma.se";              "Database" = "SCIV"};
    "Sigma Connectivity AB"             = @{"OU" = "OU=Users,OU=Sigma Connectivity,OU=SigmaGroup,DC=sigma,DC=local";                                           "Domain" = "sigmaconnectivity.se";  "Database" = ""};
    "Sigma Connectivity ApS"            = @{"OU" = "OU=Users,OU=Connectivity ApS,OU=Sigma Connectivity,OU=SigmaGroup,DC=sigma,DC=local";                       "Domain" = "sigmaconnectivity.com"; "Database" = ""};
    "Sigma Connectivity Engineering AB" = @{"OU" = "OU=Users,OU=Connectivity Engineering,OU=Sigma Connectivity,OU=SigmaGroup,DC=sigma,DC=local";               "Domain" = "sigma.se";              "Database" = "SCE"};
    "Sigma Connectivity Inc."           = @{"OU" = "OU=Users,OU=Connectivity Inc,OU=Sigma Connectivity,OU=SigmaGroup,DC=sigma,DC=local";                       "Domain" = "sigmaconnectivity.com"; "Database" = ""};
    "Sigma Connectivity Sp. z o.o."     = @{"OU" = "OU=Users,OU=Connectivity Poland,OU=Sigma Connectivity,OU=SigmaGroup,DC=sigma,DC=local";                    "Domain" = "sigmaconnectivity.com"; "Database" = "PSCT"};
    "Sigma Embedded Engineering AB"     = @{"OU" = "OU=Users,OU=Sigma Embedded Engineering,OU=SigmaGroup,DC=Sigma,DC=Local";                                   "Domain" = "sigma.se";              "Database" = "SEE"};
    "Sigma Energy & Marine AB"          = @{"OU" = "OU=Users,OU=Energy Marine,OU=Sigma Industry,OU=SigmaGroup,DC=sigma,DC=local";                              "Domain" = "sigma.se";              "Database" = "SEM"};
    "Sigma Energy & Marine AS"          = @{"OU" = "OU=Users,OU=Energy Marine Norway,OU=Sigma Industry,OU=SigmaGroup,DC=sigma,DC=local";                       "Domain" = "sigma.se";              "Database" = "SEMAS"};
    "Sigma Industry East North AB"      = @{"OU" = "OU=Users,OU=East North,OU=Sigma Industry,OU=SigmaGroup,DC=Sigma,DC=Local";                                 "Domain" = "sigma.se";              "Database" = "SIEN"};
    "Sigma Industry Evolution AB"       = @{"OU" = "OU=Users,OU=Evolution,OU=Sigma Industry,OU=SigmaGroup,DC=sigma,DC=local";                                  "Domain" = "sigma.se";              "Database" = "SIE"};
    #"Sigma Industry Inc."               = @{"OU" = "OU=Users,OU=Sigma Industry Inc,OU=Sigma Industry,OU=SigmaGroup,DC=sigma,DC=local";                         "Domain" = "sigma.se";              "Database" = ""};
    "Sigma Industry Solutions AB"       = @{"OU" = "OU=Users,OU=Solutions,OU=Sigma Industry,OU=SigmaGroup,DC=Sigma,DC=Local";                                  "Domain" = "sigma.se";              "Database" = "SSOL"};
    "Sigma Industry South AB"           = @{"OU" = "OU=Users,OU=South,OU=Sigma Industry,OU=SigmaGroup,DC=Sigma,DC=Local";                                      "Domain" = "sigma.se";              "Database" = "SISO"};
    "Sigma Industry West AB"            = @{"OU" = "OU=Users,OU=West,OU=Sigma Industry,OU=SigmaGroup,DC=Sigma,DC=Local";                                       "Domain" = "sigma.se";              "Database" = "SIW"};
    "Sigma Quality & Compliance AB"     = @{"OU" = "OU=Users,OU=Sigma Quality & Compliance,OU=SigmaGroup,DC=Sigma,DC=Local";                                   "Domain" = "sigma.se";              "Database" = "SQC"};
    "aptio group Sweden AB"             = @{"OU" = "OU=Users,OU=Sigma Quality & Compliance,OU=SigmaGroup,DC=Sigma,DC=Local";                                   "Domain" = "sigma.se";              "Database" = "SQC"};
    "Sigma Quality & Compliance ApS"    = @{"OU" = "OU=Users,OU=Quality & Compliance ApS,OU=Sigma Quality & Compliance,OU=SigmaGroup,DC=sigma,DC=local";       "Domain" = "sigma.se";              "Database" = ""}
    "aptio group Denmark ApS"           = @{"OU" = "OU=Users,OU=Quality & Compliance ApS,OU=Sigma Quality & Compliance,OU=SigmaGroup,DC=sigma,DC=local";       "Domain" = "sigma.se";              "Database" = ""}
    #"Sigma Software LLC"                = @{"OU" = "OU=Users,OU=Sigma Software,OU=SigmaGroup,DC=sigma,DC=local";                                               "Domain" = "sigma.se";              "Database" = ""}
    }
