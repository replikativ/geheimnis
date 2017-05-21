(defproject io.replikativ/geheimnis "0.1.0"
  :description "Cross-platform cryptography between cljs and clj."
  :url "https://github.com/replikativ/geheimnis"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.clojure/clojurescript "1.8.34"]
                 [org.clojure/data.codec "0.1.0"]
                 [io.replikativ/hasch "0.3.0"]]

  :plugins [[lein-cljsbuild "1.1.2"]]

  :profiles {:dev {:dependencies [[midje "1.7.0"]
                                  [com.cemerick/piggieback "0.2.1"]]
                   :figwheel {:nrepl-port 7888
                              :nrepl-middleware ["cider.nrepl/cider-middleware"
                                                 "cemerick.piggieback/wrap-cljs-repl"]}
                   :plugins [[lein-figwheel "0.5.0-2"]]}}

  :clean-targets ^{:protect false} ["target" "out" "resources/public/js"]

  :cljsbuild
  {:builds [{:id "cljs_repl"
             :source-paths ["src"]
             :figwheel true
             :compiler
             {:main geheimnis.rsa
              :asset-path "js/out"
              :libs ["gclosure/pkcs7.js" "jsbn/jsbn.js"]
              :output-to "resources/public/js/client.js"
              :output-dir "resources/public/js/out"
              :optimizations :none
              :pretty-print true}}]})
