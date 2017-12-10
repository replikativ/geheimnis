(ns geheimnis.runner
  (:require [doo.runner :refer-macros [doo-tests]]
            [geheimnis.core-test]))

(doo-tests 'geheimnis.core-test)